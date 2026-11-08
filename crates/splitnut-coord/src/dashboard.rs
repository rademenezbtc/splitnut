//! Dashboard: a static page plus a live event stream (Server-Sent Events).
//!
//! `GET /` the page, `GET /state` a snapshot (config, guardians, recent requests, Marmot
//! counters), `GET /events` live events. The relay's wire tap is fetched by the page directly
//! from the relay's own stats URL, given in the config.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};
use futures::stream::Stream;
use serde_json::{json, Value};
use splitnut_marmot::MarmotNode;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::status::{Events, Status};

const PAGE: &str = include_str!("../../../dashboard/index.html");

pub struct Dash {
    pub events: Arc<Events>,
    pub status: Arc<Status>,
    pub config: Value,
    pub marmot: Option<MarmotNode>,
}

fn marmot_json(m: &Option<MarmotNode>) -> Value {
    match m {
        Some(n) => {
            let s = n.stats();
            json!({ "ready": n.is_ready(), "sent": s.sent, "received": s.received, "bytes_out": s.bytes_out, "bytes_in": s.bytes_in })
        }
        None => Value::Null,
    }
}

async fn page() -> impl IntoResponse {
    Html(PAGE)
}

async fn state(State(d): State<Arc<Dash>>) -> impl IntoResponse {
    Json(json!({
        "config": d.config,
        "guardians": d.status.snapshot(),
        "recent": d.events.recent(),
        "marmot": marmot_json(&d.marmot),
    }))
}

async fn events(State(d): State<Arc<Dash>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(d.events.subscribe())
        .filter_map(|r| r.ok())
        .map(|v| Ok(Event::default().data(v.to_string())));
    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn serve(addr: SocketAddr, dash: Arc<Dash>) -> anyhow::Result<()> {
    // Marmot traffic counters for the page, every two seconds.
    if dash.marmot.is_some() {
        let d = dash.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(2));
            loop {
                tick.tick().await;
                let mut v = marmot_json(&d.marmot);
                v["type"] = json!("marmot");
                d.events.emit(v);
            }
        });
    }
    let app = Router::new()
        .route("/", get(page))
        .route("/state", get(state))
        .route("/events", get(events))
        .with_state(dash);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("dashboard on http://{addr}/");
    axum::serve(listener, app).await?;
    Ok(())
}
