use super::*;

pub(super) struct PathServerBlockControl {
    pub(super) request_started: std_mpsc::Receiver<()>,
    pub(super) release: std_mpsc::Sender<()>,
}

pub(super) struct PathServerBlock {
    pub(super) path: String,
    pub(super) request_started: std_mpsc::Sender<()>,
    pub(super) release: std::sync::Mutex<std_mpsc::Receiver<()>>,
}

pub(super) struct PathServer {
    pub(super) url: Url,
    pub(super) requests: Arc<AtomicU64>,
    pub(super) paths: Arc<std::sync::Mutex<Vec<String>>>,
}

impl PathServer {
    pub(super) fn spawn(routes: HashMap<String, Vec<u8>>, request_count: usize) -> Self {
        Self::spawn_with_block(routes, request_count, None)
    }

    pub(super) fn spawn_with_blocked_path(
        routes: HashMap<String, Vec<u8>>,
        request_count: usize,
        blocked_path: String,
    ) -> (Self, PathServerBlockControl) {
        let (request_started_tx, request_started) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::channel();
        let server = Self::spawn_with_block(
            routes,
            request_count,
            Some(Arc::new(PathServerBlock {
                path: blocked_path,
                request_started: request_started_tx,
                release: std::sync::Mutex::new(release_rx),
            })),
        );
        (
            server,
            PathServerBlockControl {
                request_started,
                release,
            },
        )
    }

    pub(super) fn spawn_with_block(
        routes: HashMap<String, Vec<u8>>,
        request_count: usize,
        block: Option<Arc<PathServerBlock>>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind path server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("path server url");
        let routes = Arc::new(routes);
        let requests = Arc::new(AtomicU64::new(0));
        let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
        std::thread::spawn({
            let routes = Arc::clone(&routes);
            let requests = Arc::clone(&requests);
            let paths = Arc::clone(&paths);
            move || {
                for _ in 0..request_count {
                    let (stream, _) = listener.accept().expect("accept path request");
                    requests.fetch_add(1, Ordering::AcqRel);
                    let routes = Arc::clone(&routes);
                    let block = block.clone();
                    let paths = Arc::clone(&paths);
                    std::thread::spawn(move || {
                        handle_path_request(stream, &routes, block.as_deref(), &paths);
                    });
                }
            }
        });
        Self {
            url,
            requests,
            paths,
        }
    }

    pub(super) fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Acquire)
    }

    /// Paths of the requests read so far, in arrival order.
    pub(super) fn requested_paths(&self) -> Vec<String> {
        self.paths.lock().expect("path server paths lock").clone()
    }
}

pub(super) struct GraphqlServer {
    pub(super) url: Url,
    pub(super) requests: std_mpsc::Receiver<String>,
}

pub(super) struct GraphqlServerBlock {
    pub(super) request_started: std_mpsc::Sender<()>,
    pub(super) release: std::sync::Mutex<std_mpsc::Receiver<()>>,
}

pub(super) struct JsonRpcServer {
    pub(super) url: Url,
    pub(super) requests: std_mpsc::Receiver<String>,
}

impl GraphqlServer {
    pub(super) fn spawn(responses: Vec<&'static str>) -> Self {
        Self::spawn_controlled(responses.into_iter().map(str::to_owned).collect(), None)
    }

    pub(super) fn spawn_with_blocked_response(
        responses: Vec<&'static str>,
        blocked_response: usize,
    ) -> (Self, PathServerBlockControl) {
        Self::spawn_owned_with_blocked_response(
            responses.into_iter().map(str::to_owned).collect(),
            blocked_response,
        )
    }

    pub(super) fn spawn_owned_with_blocked_response(
        responses: Vec<String>,
        blocked_response: usize,
    ) -> (Self, PathServerBlockControl) {
        let (request_started_tx, request_started) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::channel();
        let block = Arc::new(GraphqlServerBlock {
            request_started: request_started_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        let server = Self::spawn_controlled(responses, Some((blocked_response, block)));
        (
            server,
            PathServerBlockControl {
                request_started,
                release,
            },
        )
    }

    pub(super) fn spawn_controlled(
        responses: Vec<String>,
        blocked_response: Option<(usize, Arc<GraphqlServerBlock>)>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind graphql server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("graphql server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for (response_index, response) in responses.into_iter().enumerate() {
                let (stream, _) = listener.accept().expect("accept graphql request");
                let block = blocked_response.as_ref().and_then(|(index, block)| {
                    (*index == response_index).then(|| Arc::clone(block))
                });
                handle_graphql_request(stream, &response, &request_tx, block);
            }
        });
        Self { url, requests }
    }
}

impl JsonRpcServer {
    pub(super) fn spawn(responses: Vec<serde_json::Value>) -> Self {
        Self::spawn_controlled(responses, None)
    }

    pub(super) fn spawn_with_blocked_response(
        responses: Vec<serde_json::Value>,
        blocked_response: usize,
    ) -> (Self, PathServerBlockControl) {
        let (request_started_tx, request_started) = std_mpsc::channel();
        let (release, release_rx) = std_mpsc::channel();
        let block = Arc::new(GraphqlServerBlock {
            request_started: request_started_tx,
            release: std::sync::Mutex::new(release_rx),
        });
        let server = Self::spawn_controlled(responses, Some((blocked_response, block)));
        (
            server,
            PathServerBlockControl {
                request_started,
                release,
            },
        )
    }

    pub(super) fn spawn_controlled(
        responses: Vec<serde_json::Value>,
        blocked_response: Option<(usize, Arc<GraphqlServerBlock>)>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind json-rpc server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("json-rpc server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for (response_index, response) in responses.into_iter().enumerate() {
                let (stream, _) = listener.accept().expect("accept json-rpc request");
                let block = blocked_response.as_ref().and_then(|(index, block)| {
                    (*index == response_index).then(|| Arc::clone(block))
                });
                handle_json_rpc_request(stream, &response, &request_tx, block);
            }
        });
        Self { url, requests }
    }
}

pub(super) fn handle_path_request(
    mut stream: std::net::TcpStream,
    routes: &HashMap<String, Vec<u8>>,
    block: Option<&PathServerBlock>,
    paths: &std::sync::Mutex<Vec<String>>,
) {
    let path = read_request_path(&mut stream);
    paths
        .lock()
        .expect("path server paths lock")
        .push(path.clone());
    let (status, reason, body) = routes
        .get(&path)
        .map_or((404_u16, "NOT FOUND", Vec::new()), |body| {
            (200_u16, "OK", body.clone())
        });
    let headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).expect("write headers");
    // A blocked path holds its body, not its headers, so the attempt outlives
    // the gateway response-header time limit.
    if let Some(block) = block.as_ref()
        && block.path == path
    {
        stream.flush().expect("flush blocked path headers");
        block
            .request_started
            .send(())
            .expect("signal blocked path request");
        block
            .release
            .lock()
            .expect("blocked path release lock")
            .recv()
            .expect("release blocked path request");
    }
    stream.write_all(&body).expect("write body");
}

pub(super) fn handle_graphql_request(
    mut stream: std::net::TcpStream,
    response: &str,
    requests: &std_mpsc::Sender<String>,
    block: Option<Arc<GraphqlServerBlock>>,
) {
    let request = read_http_request(&mut stream);
    requests.send(request).expect("record graphql request");
    if let Some(block) = block {
        block
            .request_started
            .send(())
            .expect("signal blocked GraphQL response");
        block
            .release
            .lock()
            .expect("blocked GraphQL release lock")
            .recv()
            .expect("release blocked GraphQL response");
    }
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(response.as_bytes());
}

pub(super) fn handle_json_rpc_request(
    mut stream: std::net::TcpStream,
    response: &serde_json::Value,
    requests: &std_mpsc::Sender<String>,
    block: Option<Arc<GraphqlServerBlock>>,
) {
    let request = read_http_request(&mut stream);
    requests
        .send(request.clone())
        .expect("record json-rpc request");
    if let Some(block) = block {
        block
            .request_started
            .send(())
            .expect("signal blocked JSON-RPC response");
        block
            .release
            .lock()
            .expect("blocked JSON-RPC release lock")
            .recv()
            .expect("release blocked JSON-RPC response");
    }
    let body_start = request
        .find("\r\n\r\n")
        .map_or(request.len(), |index| index + 4);
    let id = serde_json::from_str::<serde_json::Value>(&request[body_start..])
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or_else(|| serde_json::json!(1));
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": response,
    })
    .to_string();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let result = stream
        .write_all(headers.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()));
    if let Err(error) = result {
        // Hedge losers may close their connection before a blocked fixture response is released.
        assert!(
            matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::NotConnected
            ),
            "write JSON-RPC response: {error}"
        );
    }
}

pub(super) fn read_request_path(stream: &mut std::net::TcpStream) -> String {
    read_http_request(stream)
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_string()
}

pub(super) fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf).expect("read request");
        assert!(read > 0, "client closed before request headers");
        request.extend_from_slice(&buf[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("header terminator")
        + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let mut content_length = 0_usize;
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().expect("content length");
        }
    }
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buf).expect("read request body");
        assert!(read > 0, "client closed before request body");
        request.extend_from_slice(&buf[..read]);
    }
    String::from_utf8_lossy(&request).to_string()
}

impl JsonRpcServer {
    /// Serves every request with `handler`, which maps the parsed request body
    /// to the response's `result` or `error` member.
    pub(super) fn spawn_handler(
        handler: impl Fn(&serde_json::Value) -> serde_json::Value + Send + 'static,
    ) -> Self {
        Self::spawn_handler_with_status(move |body| Ok(handler(body)))
    }

    /// Like `spawn_handler`, but a handler `Err(status)` answers with that
    /// HTTP status and an empty body.
    pub(super) fn spawn_handler_with_status(
        handler: impl Fn(&serde_json::Value) -> Result<serde_json::Value, u16> + Send + 'static,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind json-rpc server");
        let url = Url::parse(&format!(
            "http://{}",
            listener.local_addr().expect("local addr")
        ))
        .expect("json-rpc server url");
        let (request_tx, requests) = std_mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.expect("accept json-rpc request");
                let request = read_http_request(&mut stream);
                let body = json_rpc_request_body(&request);
                if request_tx.send(request).is_err() {
                    break;
                }
                let (status, response) = match handler(&body) {
                    Ok(mut response) => {
                        response["jsonrpc"] = serde_json::json!("2.0");
                        response["id"] = body["id"].clone();
                        (200, response.to_string())
                    }
                    Err(status) => (status, String::new()),
                };
                let headers = format!(
                    "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    if status == 200 { "OK" } else { "Error" },
                    response.len()
                );
                let _ = stream
                    .write_all(headers.as_bytes())
                    .and_then(|()| stream.write_all(response.as_bytes()));
            }
        });
        Self { url, requests }
    }

    pub(super) fn drain_request_bodies(&self) -> Vec<serde_json::Value> {
        self.requests
            .try_iter()
            .map(|request| json_rpc_request_body(&request))
            .collect()
    }
}

pub(super) fn json_rpc_request_body(request: &str) -> serde_json::Value {
    let body_start = request
        .find("\r\n\r\n")
        .map_or(request.len(), |index| index + 4);
    serde_json::from_str(&request[body_start..]).expect("json-rpc request body")
}

/// Binds a listener that never accepts: connections complete in the backlog,
/// and requests on them never receive response headers.
pub(super) fn silent_server() -> (std::net::TcpListener, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind silent server");
    let port = listener.local_addr().expect("silent server addr").port();
    (listener, port)
}

/// Accepts and closes every connection waiting on `listener`, returning how
/// many there were.
pub(super) fn drain_backlog_connections(listener: &std::net::TcpListener) -> usize {
    listener
        .set_nonblocking(true)
        .expect("nonblocking silent server");
    std::iter::from_fn(|| listener.accept().ok()).count()
}

pub(super) fn credential_url(port: u16) -> Url {
    Url::parse(&format!("http://user:secret@127.0.0.1:{port}/key-abc"))
        .expect("credential-bearing URL")
}
