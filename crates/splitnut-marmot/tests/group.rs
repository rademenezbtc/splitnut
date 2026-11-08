//! Transport-level integration test against an in-process relay.

use std::time::Duration;

use nostr_relay_builder::prelude::*;
use nostr_sdk::Client;
use splitnut_marmot::{MarmotNode, NodeConfig, Role, Storage};
use tokio::sync::broadcast;

async fn relay() -> (LocalRelay, String) {
    let relay = LocalRelay::new(RelayBuilder::default());
    relay.run().await.unwrap();
    let url = relay.url().await.to_string();
    (relay, url)
}

async fn recv_from(rx: &mut broadcast::Receiver<splitnut_marmot::Incoming>, secs: u64) -> splitnut_marmot::Incoming {
    tokio::time::timeout(Duration::from_secs(secs), rx.recv()).await.expect("timed out").expect("closed")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_forms_messages_flow_and_relay_sees_ciphertext() {
    let _ = tracing_subscriber::fmt().with_env_filter("splitnut_marmot=info").try_init();
    let (_relay, url) = relay().await;
    let dir = std::env::temp_dir().join(format!("sn-marmot-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let coord_keys = Keys::generate();
    let g_keys: Vec<Keys> = (0..3).map(|_| Keys::generate()).collect();

    let mut guardians = vec![];
    for (i, k) in g_keys.iter().enumerate() {
        let storage = Storage::File(dir.join(format!("g{i}.sqlite")));
        let cfg = NodeConfig { keys: k.clone(), relays: vec![url.clone()], storage, role: Role::Guardian { coordinator: coord_keys.public_key() } };
        guardians.push(MarmotNode::start(cfg).await.unwrap());
    }
    let coord = MarmotNode::start(NodeConfig {
        keys: coord_keys.clone(),
        relays: vec![url.clone()],
        storage: Storage::Memory,
        role: Role::Coordinator { guardians: g_keys.iter().map(|k| k.public_key()).collect() },
    })
    .await
    .unwrap();

    assert!(coord.wait_ready(Duration::from_secs(30)).await, "coordinator created the group");
    for g in &guardians {
        assert!(g.wait_ready(Duration::from_secs(30)).await, "guardian joined");
    }

    // coordinator -> all guardians
    let mut g_rx: Vec<_> = guardians.iter().map(|g| g.subscribe()).collect();
    let mut c_rx = coord.subscribe();
    coord.send(r#"{"req":1,"hello":"guardians"}"#.into()).await.unwrap();
    for rx in &mut g_rx {
        let m = recv_from(rx, 10).await;
        assert_eq!(m.from, coord_keys.public_key(), "sender is authenticated");
        assert!(m.content.contains("hello"));
    }

    // each guardian -> coordinator
    for (i, g) in guardians.iter().enumerate() {
        g.send(format!(r#"{{"req":1,"from":{i}}}"#)).await.unwrap();
    }
    let mut senders = vec![];
    for _ in 0..3 {
        senders.push(recv_from(&mut c_rx, 10).await.from);
    }
    for k in &g_keys {
        assert!(senders.contains(&k.public_key()));
    }

    // relay saw only ciphertext: no plaintext marker in any stored event
    let client = Client::default();
    client.add_relay(&url).await.unwrap();
    client.connect().await;
    let all = client.fetch_events(Filter::new(), Duration::from_secs(5)).await.unwrap();
    let kinds: Vec<u16> = all.iter().map(|e| e.kind.as_u16()).collect();
    assert!(kinds.contains(&445) && kinds.contains(&1059), "kinds seen: {kinds:?}");
    for e in all.iter() {
        assert!(!e.content.contains("\"req\"") && !e.content.contains("hello"), "plaintext on relay in kind {}", e.kind);
    }

    // restart guardian 0 from its encrypted database: it resumes the group without a new welcome
    guardians[0].shutdown().await;
    let restarted = MarmotNode::start(NodeConfig {
        keys: g_keys[0].clone(),
        relays: vec![url.clone()],
        storage: Storage::File(dir.join("g0.sqlite")),
        role: Role::Guardian { coordinator: coord_keys.public_key() },
    })
    .await
    .unwrap();
    assert!(restarted.wait_ready(Duration::from_secs(5)).await, "resumed from storage");
    let mut r_rx = restarted.subscribe();
    tokio::time::sleep(Duration::from_millis(500)).await;
    coord.send(r#"{"req":2}"#.into()).await.unwrap();
    // it may first see replayed history; wait for the new message
    loop {
        let m = recv_from(&mut r_rx, 10).await;
        if m.content.contains("\"req\":2") {
            break;
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
