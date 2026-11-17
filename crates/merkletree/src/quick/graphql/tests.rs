use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use reqwest::Client;
use serde::Deserialize;

use super::{
    EmptyVariables, GraphPostError, GraphTimeoutPhase, SQUID_BODY_IDLE_TIMEOUT, post_graphql_data,
    post_graphql_data_once,
};

#[derive(Debug, Deserialize)]
struct TestData {
    ok: bool,
}

#[tokio::test]
async fn post_graphql_data_retries_request_stage_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let endpoint = url::Url::parse(&format!(
        "http://{}/graphql",
        listener.local_addr().expect("read test server address")
    ))
    .expect("parse test server URL");
    let (done_tx, done_rx) = mpsc::channel();

    let server = thread::spawn(move || {
        let (first_stream, _) = listener.accept().expect("accept first request");
        drop(first_stream);

        let (mut second_stream, _) = listener.accept().expect("accept retry request");
        second_stream
            .set_read_timeout(Some(StdDuration::from_secs(5)))
            .expect("set retry read timeout");
        read_http_request(&mut second_stream);

        let body = r#"{"data":{"ok":true}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        second_stream
            .write_all(response.as_bytes())
            .expect("write retry response");
        done_tx.send(()).expect("send server completion");
    });

    let client = Client::builder().no_proxy().build().expect("build client");
    let data: TestData =
        post_graphql_data(&client, &endpoint, "query Test { ok }", &EmptyVariables {})
            .await
            .expect("request should succeed after retry");

    assert!(data.ok);
    done_rx
        .recv_timeout(StdDuration::from_secs(5))
        .expect("server should observe retry request");
    server.join().expect("server thread should finish");
}

/// A response whose headers never arrive times out and is retried, and
/// retry warnings carry the error class but not the credential-bearing
/// endpoint, even for a transport error whose text embeds the URL.
#[tokio::test]
async fn post_graphql_data_retries_header_stall_without_logging_endpoint() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let port = listener
        .local_addr()
        .expect("read test server address")
        .port();
    let endpoint = url::Url::parse(&format!(
        "http://user:secret@127.0.0.1:{port}/graphql?key=secret"
    ))
    .expect("parse test server URL");

    let server = thread::spawn(move || {
        // Reads the first request and never answers it.
        let (mut stalled_stream, _) = listener.accept().expect("accept stalled request");
        stalled_stream
            .set_read_timeout(Some(StdDuration::from_secs(5)))
            .expect("set stalled read timeout");
        read_http_request(&mut stalled_stream);

        let (dropped_stream, _) = listener.accept().expect("accept dropped request");
        drop(dropped_stream);

        let (mut stream, _) = listener.accept().expect("accept final retry");
        stream
            .set_read_timeout(Some(StdDuration::from_secs(5)))
            .expect("set retry read timeout");
        read_http_request(&mut stream);
        let body = r#"{"data":{"ok":true}}"#;
        stream
            .write_all(format!("{}{body}", json_response_head(body.len())).as_bytes())
            .expect("write retry response");
        drop(stalled_stream);
    });

    let events = CapturedEvents::default();
    let guard = events.capture();
    let client = Client::builder().no_proxy().build().expect("build client");
    let data: TestData =
        post_graphql_data(&client, &endpoint, "query Test { ok }", &EmptyVariables {})
            .await
            .expect("request should succeed after retries");
    drop(guard);

    assert!(data.ok);
    server.join().expect("server thread should finish");

    let retries = events
        .events()
        .into_iter()
        .filter(|event| {
            event
                .get("message")
                .is_some_and(|message| message == "quick-sync GraphQL request failed; retrying")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        retries.len(),
        2,
        "one retry per failed attempt: {retries:?}"
    );
    assert_eq!(retries[0].get("attempt").map(String::as_str), Some("1"));
    assert_eq!(
        retries[0].get("error_class").map(String::as_str),
        Some("timeout_headers")
    );
    assert!(
        retries
            .iter()
            .all(|retry| retry.contains_key("delay_ms") && retry.contains_key("error_class")),
        "retry warnings carry the delay and error class: {retries:?}"
    );
    let forbidden = ["127.0.0.1", "user", "secret"];
    for event in events.events() {
        for value in event.values() {
            assert!(
                forbidden.iter().all(|needle| !value.contains(needle)),
                "log value {value:?} exposes the endpoint"
            );
        }
    }
}

#[tokio::test]
async fn post_graphql_data_once_times_out_stalled_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let endpoint = url::Url::parse(&format!(
        "http://{}/graphql",
        listener.local_addr().expect("read test server address")
    ))
    .expect("parse test server URL");
    let (done_tx, done_rx) = mpsc::channel::<()>();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        stream
            .set_read_timeout(Some(StdDuration::from_secs(5)))
            .expect("set read timeout");
        read_http_request(&mut stream);
        let body = r#"{"data":{"ok":true}}"#;
        stream
            .write_all(format!("{}{}", json_response_head(body.len()), &body[..8]).as_bytes())
            .expect("write partial response");
        // Holds the connection open without sending the rest of the body.
        let _ = done_rx.recv();
    });

    let client = Client::builder().no_proxy().build().expect("build client");
    let error = post_graphql_data_once::<TestData, _>(
        &client,
        &endpoint,
        "query Test { ok }",
        &EmptyVariables {},
    )
    .await
    .expect_err("stalled body should time out");
    drop(done_tx);

    assert!(
        matches!(
            error,
            GraphPostError::Timeout {
                phase: GraphTimeoutPhase::Body
            }
        ),
        "unexpected error: {error}"
    );
    assert!(error.is_retryable());
    server.join().expect("server thread should finish");
}

#[tokio::test]
async fn post_graphql_data_once_completes_body_that_keeps_arriving() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let endpoint = url::Url::parse(&format!(
        "http://{}/graphql",
        listener.local_addr().expect("read test server address")
    ))
    .expect("parse test server URL");

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept request");
        stream
            .set_read_timeout(Some(StdDuration::from_secs(5)))
            .expect("set read timeout");
        stream.set_nodelay(true).expect("disable Nagle");
        read_http_request(&mut stream);
        let body = r#"{"data":{"ok":true}}"#;
        stream
            .write_all(json_response_head(body.len()).as_bytes())
            .expect("write response head");
        // Seven gaps of a fifth of the idle timeout outlast it in total.
        for piece in body.as_bytes().chunks(3) {
            thread::sleep(SQUID_BODY_IDLE_TIMEOUT / 5);
            stream.write_all(piece).expect("write body piece");
        }
    });

    let client = Client::builder().no_proxy().build().expect("build client");
    let started = Instant::now();
    let data = post_graphql_data_once::<TestData, _>(
        &client,
        &endpoint,
        "query Test { ok }",
        &EmptyVariables {},
    )
    .await
    .expect("a body that keeps arriving should complete");

    assert!(data.ok);
    assert!(started.elapsed() > SQUID_BODY_IDLE_TIMEOUT);
    server.join().expect("server thread should finish");
}

fn json_response_head(content_length: usize) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
    )
}

/// Records `merkletree` tracing events as field-name to value maps.
#[derive(Clone, Default)]
struct CapturedEvents(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

impl CapturedEvents {
    fn capture(&self) -> CaptureGuard {
        // With one registered dispatcher, tracing-core resolves a callsite
        // first hit on another test thread against that thread's empty
        // default and caches it as disabled. A second live dispatcher keeps
        // interest computed across every registered dispatcher, including
        // this thread's capture.
        let registered = tracing::Dispatch::new(CaptureSubscriber(self.clone()));
        CaptureGuard {
            _default: tracing::subscriber::set_default(CaptureSubscriber(self.clone())),
            _registered: registered,
        }
    }

    fn events(&self) -> Vec<BTreeMap<String, String>> {
        self.0.lock().expect("captured events lock").clone()
    }
}

struct CaptureGuard {
    _default: tracing::subscriber::DefaultGuard,
    _registered: tracing::Dispatch,
}

struct CaptureSubscriber(CapturedEvents);

struct CapturedFields<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for CapturedFields<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl tracing::Subscriber for CaptureSubscriber {
    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("merkletree")
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut CapturedFields(&mut fields));
        self.0.0.lock().expect("captured events lock").push(fields);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

fn read_http_request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];

    loop {
        let read = stream.read(&mut buffer).expect("read retry request");
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request_is_complete(&request) {
            break;
        }
    }

    assert!(request.starts_with(b"POST "));
}

fn request_is_complete(request: &[u8]) -> bool {
    let Some(header_end) = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
    else {
        return false;
    };
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().expect("parse content length"))
        })
        .unwrap_or(0);

    request.len() >= header_end + content_length
}
