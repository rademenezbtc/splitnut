//! SplitNut's Marmot transport: one encrypted MLS group over Nostr joining the coordinator
//! and the guardians. Relays see only gift wraps and MLS ciphertext.
//!
//! A [`MarmotNode`] is an actor: a single tokio task owns the MDK instance and the Nostr
//! client, and every MLS operation (create, welcome, encrypt, decrypt) happens in that task,
//! one at a time. That rules out the "send overlapping with processing" message loss seen in
//! BlackIce, by construction rather than by locking.
//!
//! Setup:
//! * a guardian publishes a key package and waits for a welcome gift-wrapped by the pinned
//!   coordinator key; it accepts nothing from anyone else;
//! * the coordinator waits until every guardian's key package is on the relays, creates the
//!   group (itself the only admin) and gift-wraps one welcome per guardian.
//!
//! MLS state lives in SQLite, so a restarted node resumes its group without a new setup.
//! MDK binds every application message to the sender's MLS credential, so [`Incoming::from`]
//! is authenticated; callers map it to a guardian index.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use mdk_core::messages::MessageProcessingResult;
use mdk_core::prelude::*;
use mdk_sqlite_storage::MdkSqliteStorage;
use nostr_sdk::hashes::sha256::Hash as Sha256Hash;
use nostr_sdk::hashes::Hash;
use nostr_sdk::prelude::*;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::{debug, info, warn};

/// Inner event kind for SplitNut payloads inside the group.
const PAYLOAD_KIND: u16 = 9;
const GROUP_NAME: &str = "SplitNut guardians";
const RETRY: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
pub enum MarmotError {
    #[error("node stopped")]
    Stopped,
    #[error("not in a group yet")]
    NotReady,
    #[error("mdk: {0}")]
    Mdk(String),
    #[error("relay: {0}")]
    Relay(String),
}

/// A decrypted application message from another group member.
#[derive(Clone, Debug)]
pub struct Incoming {
    /// Authenticated sender (bound to its MLS credential by MDK).
    pub from: PublicKey,
    pub content: String,
    /// The sender's timestamp on the inner event.
    pub created_at: Timestamp,
}

/// Counters for the dashboard.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub sent: u64,
    pub received: u64,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Clone, Debug)]
pub enum Role {
    /// Creates the group with exactly these guardians.
    Coordinator { guardians: Vec<PublicKey> },
    /// Joins only a group created by this coordinator.
    Guardian { coordinator: PublicKey },
}

#[derive(Clone, Debug)]
pub enum Storage {
    /// SQLCipher database at this path (created if missing); survives restarts.
    File(PathBuf),
    /// Throwaway database in the temp directory, for tests.
    Memory,
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub keys: Keys,
    pub relays: Vec<String>,
    pub storage: Storage,
    pub role: Role,
}

enum Command {
    Send(String, oneshot::Sender<Result<(), MarmotError>>),
    Shutdown(oneshot::Sender<()>),
}

/// Handle to a running node.
#[derive(Clone)]
pub struct MarmotNode {
    cmd: mpsc::Sender<Command>,
    incoming: broadcast::Sender<Incoming>,
    ready: watch::Receiver<bool>,
    stats: watch::Receiver<Stats>,
    pubkey: PublicKey,
}

impl MarmotNode {
    /// Connect to the relays and start the actor. Group setup continues in the background;
    /// see [`Self::wait_ready`].
    pub async fn start(cfg: NodeConfig) -> anyhow::Result<Self> {
        let path = match &cfg.storage {
            Storage::File(p) => p.clone(),
            Storage::Memory => std::env::temp_dir().join(format!("splitnut-mls-{}.sqlite", Keys::generate().public_key().to_hex())),
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // SQLCipher key derived from the node's Nostr secret: MLS state is encrypted at rest
        // and only this identity can reopen it.
        let db_key: [u8; 32] = Sha256Hash::hash(
            &[b"splitnut-mls-db-v1".as_slice(), cfg.keys.secret_key().as_secret_bytes()].concat(),
        )
        .to_byte_array();
        let storage = MdkSqliteStorage::new_with_key(&path, mdk_sqlite_storage::EncryptionConfig::new(db_key))?;
        let mdk = MDK::new(storage);
        let client = Client::builder().signer(cfg.keys.clone()).build();
        for r in &cfg.relays {
            client.add_relay(r.as_str()).await?;
        }
        client.connect().await;
        client.wait_for_connection(Duration::from_secs(5)).await;

        let relays = cfg.relays.iter().map(|r| RelayUrl::parse(r)).collect::<Result<Vec<_>, _>>()?;
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let (incoming, _) = broadcast::channel(1024);
        let (ready_tx, ready) = watch::channel(false);
        let (stats_tx, stats) = watch::channel(Stats::default());
        let pubkey = cfg.keys.public_key();

        let actor = Actor {
            keys: cfg.keys,
            role: cfg.role,
            relays,
            mdk,
            client,
            group: None,
            incoming: incoming.clone(),
            ready: ready_tx,
            stats: stats_tx,
            key_package_ids: vec![],
        };
        tokio::spawn(actor.run(cmd_rx));
        Ok(Self { cmd: cmd_tx, incoming, ready, stats, pubkey })
    }

    pub fn pubkey(&self) -> PublicKey {
        self.pubkey
    }

    /// Wait until the node is in the group. Returns false on timeout.
    pub async fn wait_ready(&self, timeout: Duration) -> bool {
        let mut rx = self.ready.clone();
        tokio::time::timeout(timeout, rx.wait_for(|r| *r)).await.map(|r| r.is_ok()).unwrap_or(false)
    }

    pub fn is_ready(&self) -> bool {
        *self.ready.borrow()
    }

    /// Encrypt `content` to the group and publish it.
    pub async fn send(&self, content: String) -> Result<(), MarmotError> {
        let (tx, rx) = oneshot::channel();
        self.cmd.send(Command::Send(content, tx)).await.map_err(|_| MarmotError::Stopped)?;
        rx.await.map_err(|_| MarmotError::Stopped)?
    }

    /// Disconnect from the relays and stop the actor (its database stays on disk).
    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Command::Shutdown(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }

    /// Decrypted messages from other members.
    pub fn subscribe(&self) -> broadcast::Receiver<Incoming> {
        self.incoming.subscribe()
    }

    pub fn stats(&self) -> Stats {
        self.stats.borrow().clone()
    }
}

struct GroupRef {
    mls_group_id: GroupId,
    nostr_group_id: String,
}

struct Actor {
    keys: Keys,
    role: Role,
    relays: Vec<RelayUrl>,
    mdk: MDK<MdkSqliteStorage>,
    client: Client,
    group: Option<GroupRef>,
    incoming: broadcast::Sender<Incoming>,
    ready: watch::Sender<bool>,
    stats: watch::Sender<Stats>,
    key_package_ids: Vec<EventId>,
}

impl Actor {
    async fn run(mut self, mut cmd_rx: mpsc::Receiver<Command>) {
        let mut notifications = self.client.notifications();
        // Resume an existing group, or start setup.
        match self.mdk.get_groups() {
            Ok(groups) if !groups.is_empty() => {
                let g = &groups[0];
                self.enter_group(g.mls_group_id.clone(), hex::encode(g.nostr_group_id)).await;
                info!(group = %self.group.as_ref().unwrap().nostr_group_id, "resumed existing group");
            }
            Ok(_) => self.begin_setup().await,
            Err(e) => warn!("reading groups: {e}"),
        }

        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + RETRY, RETRY);
        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => match cmd {
                    Some(Command::Send(content, reply)) => {
                        let r = self.send(content).await;
                        let _ = reply.send(r);
                    }
                    Some(Command::Shutdown(done)) => {
                        self.client.shutdown().await;
                        let _ = done.send(());
                        break;
                    }
                    None => break,
                },
                n = notifications.recv() => match n {
                    Ok(RelayPoolNotification::Event { event, .. }) => self.on_event(&event).await,
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(k)) => warn!("dropped {k} relay notifications"),
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                _ = tick.tick() => {
                    if self.group.is_none() {
                        self.retry_setup().await;
                    }
                }
            }
        }
    }

    async fn begin_setup(&mut self) {
        match self.role.clone() {
            Role::Guardian { .. } => {
                let f = Filter::new().kind(Kind::GiftWrap).pubkey(self.keys.public_key());
                if let Err(e) = self.client.subscribe(f, None).await {
                    warn!("subscribing to welcomes: {e}");
                }
                self.publish_key_package().await;
            }
            Role::Coordinator { .. } => self.try_create_group().await,
        }
    }

    async fn retry_setup(&mut self) {
        match self.role.clone() {
            // Re-publish until a welcome arrives (relays may have been down or dropped it).
            Role::Guardian { .. } => self.publish_key_package().await,
            Role::Coordinator { .. } => self.try_create_group().await,
        }
    }

    async fn publish_key_package(&mut self) {
        let data = match self.mdk.create_key_package_for_event(&self.keys.public_key(), self.relays.clone()) {
            Ok(d) => d,
            Err(e) => return warn!("creating key package: {e}"),
        };
        for (kind, tags) in [(Kind::Custom(30443), data.tags_30443), (Kind::MlsKeyPackage, data.tags_443)] {
            match EventBuilder::new(kind, data.content.clone()).tags(tags).sign_with_keys(&self.keys) {
                Ok(ev) => match self.client.send_event(&ev).await {
                    Ok(out) if !out.success.is_empty() => {
                        debug!(kind = kind.as_u16(), "key package published");
                        self.key_package_ids.push(ev.id);
                    }
                    Ok(out) => warn!(kind = kind.as_u16(), "key package not accepted: {:?}", out.failed),
                    Err(e) => warn!("publishing key package: {e}"),
                },
                Err(e) => warn!("signing key package: {e}"),
            }
        }
        info!("key package published; waiting for the coordinator's welcome");
    }

    async fn try_create_group(&mut self) {
        let Role::Coordinator { guardians } = self.role.clone() else { return };
        let filter = Filter::new().kind(Kind::Custom(30443)).authors(guardians.clone());
        let events = match self.client.fetch_events(filter, Duration::from_secs(5)).await {
            Ok(evs) => evs,
            Err(e) => return warn!("fetching key packages: {e}"),
        };
        // Latest key package per guardian.
        let mut latest: HashMap<PublicKey, Event> = HashMap::new();
        for ev in events {
            match latest.get(&ev.pubkey) {
                Some(cur) if cur.created_at >= ev.created_at => {}
                _ => {
                    latest.insert(ev.pubkey, ev);
                }
            }
        }
        let missing: Vec<String> = guardians
            .iter()
            .filter(|g| !latest.contains_key(*g))
            .map(|g| g.to_bech32().unwrap_or_else(|_| g.to_hex()))
            .collect();
        if !missing.is_empty() {
            return info!(waiting_for = ?missing, "waiting for guardian key packages");
        }
        let kp_events: Vec<Event> = guardians.iter().map(|g| latest[g].clone()).collect();
        let config = NostrGroupConfigData::new(
            GROUP_NAME.to_string(),
            "Threshold mint guardians".to_string(),
            None,
            None,
            None,
            self.relays.clone(),
            vec![self.keys.public_key()],
        );
        let result = match self.mdk.create_group(&self.keys.public_key(), kp_events.clone(), config) {
            Ok(r) => r,
            Err(e) => return warn!("creating group: {e}"),
        };
        // Welcome rumors come back in key-package order, each tagged with its key package id.
        for (rumor, kp) in result.welcome_rumors.into_iter().zip(&kp_events) {
            match EventBuilder::gift_wrap(&self.keys, &kp.pubkey, rumor, []).await {
                Ok(wrap) => match self.client.send_event(&wrap).await {
                    Ok(out) if !out.success.is_empty() => info!(guardian = %kp.pubkey.to_bech32().unwrap_or_default(), "welcome sent"),
                    Ok(out) => warn!("welcome not accepted by any relay: {:?}", out.failed),
                    Err(e) => warn!("sending welcome: {e}"),
                },
                Err(e) => warn!("gift-wrapping welcome: {e}"),
            }
        }
        let g = result.group;
        self.enter_group(g.mls_group_id, hex::encode(g.nostr_group_id)).await;
        info!(members = guardians.len() + 1, "group created");
    }

    async fn enter_group(&mut self, mls_group_id: GroupId, nostr_group_id: String) {
        let f = Filter::new()
            .kind(Kind::MlsGroupMessage)
            .custom_tag(SingleLetterTag::lowercase(Alphabet::H), nostr_group_id.clone());
        if let Err(e) = self.client.subscribe(f, None).await {
            warn!("subscribing to group messages: {e}");
        }
        self.group = Some(GroupRef { mls_group_id, nostr_group_id });
        let _ = self.ready.send(true);
    }

    async fn on_event(&mut self, event: &Event) {
        match event.kind {
            Kind::GiftWrap => self.on_gift_wrap(event).await,
            Kind::MlsGroupMessage => self.on_group_message(event),
            _ => {}
        }
    }

    async fn on_gift_wrap(&mut self, event: &Event) {
        let Role::Guardian { coordinator } = self.role else { return };
        if self.group.is_some() {
            return;
        }
        let gift = match self.client.unwrap_gift_wrap(event).await {
            Ok(g) => g,
            Err(e) => return debug!("unwrapping gift wrap: {e}"),
        };
        // Pin: only the configured coordinator may invite this guardian.
        if gift.sender != coordinator || gift.rumor.pubkey != coordinator || gift.rumor.kind != Kind::MlsWelcome {
            return warn!(sender = %gift.sender, "ignoring welcome from an unexpected sender");
        }
        if let Err(e) = self.mdk.process_welcome(&event.id, &gift.rumor) {
            return warn!("processing welcome: {e}");
        }
        let pending = match self.mdk.get_pending_welcomes(None) {
            Ok(p) => p,
            Err(e) => return warn!("reading welcomes: {e}"),
        };
        let Some(welcome) = pending.into_iter().find(|w| w.welcomer == coordinator) else {
            return warn!("welcome processed but not pending");
        };
        if let Err(e) = self.mdk.accept_welcome(&welcome) {
            return warn!("accepting welcome: {e}");
        }
        let nostr_group_id = hex::encode(welcome.nostr_group_id);
        self.enter_group(welcome.mls_group_id.clone(), nostr_group_id.clone()).await;
        info!(group = %nostr_group_id, "joined the guardian group");
    }

    fn on_group_message(&mut self, event: &Event) {
        match self.mdk.process_message(event) {
            Ok(MessageProcessingResult::ApplicationMessage(m)) => {
                if m.pubkey == self.keys.public_key() || m.kind != Kind::Custom(PAYLOAD_KIND) {
                    return;
                }
                self.stats.send_modify(|s| {
                    s.received += 1;
                    s.bytes_in += event.content.len() as u64;
                });
                let _ = self.incoming.send(Incoming { from: m.pubkey, content: m.content, created_at: m.created_at });
            }
            Ok(other) => debug!("group event: {other:?}"),
            Err(e) => debug!("group message not processed: {e}"),
        }
    }

    async fn send(&mut self, content: String) -> Result<(), MarmotError> {
        let group = self.group.as_ref().ok_or(MarmotError::NotReady)?;
        let rumor = EventBuilder::new(Kind::Custom(PAYLOAD_KIND), content).build(self.keys.public_key());
        let event = self
            .mdk
            .create_message(&group.mls_group_id, rumor, None)
            .map_err(|e| MarmotError::Mdk(e.to_string()))?;
        let out = self.client.send_event(&event).await.map_err(|e| MarmotError::Relay(e.to_string()))?;
        if out.success.is_empty() {
            return Err(MarmotError::Relay(format!("no relay accepted the message: {:?}", out.failed)));
        }
        self.stats.send_modify(|s| {
            s.sent += 1;
            s.bytes_out += event.content.len() as u64;
        });
        Ok(())
    }
}

/// Load a Nostr secret key from `path`, or generate one and write it there (mode 0600).
pub fn load_or_create_keys(path: &std::path::Path) -> anyhow::Result<Keys> {
    if path.exists() {
        let s = std::fs::read_to_string(path)?;
        return Ok(Keys::parse(s.trim())?);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32()?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        f.write_all(nsec.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, nsec)?;
    Ok(keys)
}

pub use nostr_sdk::prelude::{Keys as NostrKeys, PublicKey as NostrPublicKey, Timestamp as NostrTimestamp, ToBech32 as NostrToBech32};
