//! Transport-agnostic model of captured HTTP traffic and the event bus that
//! fans it out to sinks (stdout now; the history store, UI and scanner later).

pub mod dto;
pub mod events;
pub mod ids;
pub mod message;

pub use dto::{
    BodyView, RequestView, ResponseView, TransactionSummary, TransactionView, epoch_millis,
};
pub use events::{EventBus, StdoutSink, TrafficEvent, TrafficSink, WsDirection, WsMessageEvent};
pub use ids::TransactionIds;
pub use message::{CapturedRequest, CapturedResponse, Header, HttpService, Transaction};
