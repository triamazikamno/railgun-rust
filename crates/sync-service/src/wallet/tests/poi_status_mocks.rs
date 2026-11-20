use super::*;

#[derive(Default)]
pub(super) struct RecordingPoiStatusClient {
    pub(super) calls: Mutex<Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)>>,
    pub(super) fail_calls: Mutex<HashSet<usize>>,
    pub(super) default_status: Mutex<Option<PoiStatus>>,
    pub(super) statuses: Mutex<HashMap<FixedBytes<32>, PoiStatus>>,
}

pub(super) struct MockPoiRpc {
    pub(super) url: Url,
    pub(super) requests: std_mpsc::Receiver<serde_json::Value>,
}

impl RecordingPoiStatusClient {
    pub(super) fn fail_call(&self, call_index: usize) {
        self.fail_calls
            .lock()
            .expect("fail calls")
            .insert(call_index);
    }

    pub(super) fn set_default_status(&self, status: PoiStatus) {
        *self.default_status.lock().expect("default status") = Some(status);
    }

    pub(super) fn calls(&self) -> Vec<(Vec<FixedBytes<32>>, Vec<BlindedCommitmentData>)> {
        self.calls.lock().expect("poi calls").clone()
    }
}

pub(super) async fn spawn_poi_rpc(result: serde_json::Value) -> MockPoiRpc {
    spawn_poi_rpc_sequence(vec![result]).await
}

pub(super) async fn spawn_poi_rpc_sequence(results: Vec<serde_json::Value>) -> MockPoiRpc {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock POI RPC");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock POI RPC URL");
    let (tx, requests) = std_mpsc::channel();
    tokio::spawn(async move {
        for result in results {
            let (mut socket, _) = listener.accept().await.expect("accept request");
            let mut bytes = Vec::new();
            let mut buf = [0_u8; 1024];
            let (body_start, content_length) = loop {
                let read = socket.read(&mut buf).await.expect("read request");
                assert!(
                    read > 0,
                    "mock POI RPC connection closed before request body"
                );
                bytes.extend_from_slice(&buf[..read]);
                if let Some(lengths) = http_body_bounds(&bytes) {
                    break lengths;
                }
            };
            let body = &bytes[body_start..body_start + content_length];
            let request: serde_json::Value = serde_json::from_slice(body).expect("request JSON");
            tx.send(request.clone()).expect("record request");
            let response = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"].clone(),
                "result": result,
            })
            .to_string();
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            );
            socket
                .write_all(headers.as_bytes())
                .await
                .expect("write headers");
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write body");
        }
    });
    MockPoiRpc { url, requests }
}

pub(super) async fn spawn_http_response(body: Vec<u8>) -> (Url, std_mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock HTTP server");
    let url = Url::parse(&format!(
        "http://{}",
        listener.local_addr().expect("local addr")
    ))
    .expect("mock HTTP URL");
    let (tx, requests) = std_mpsc::channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept request");
        let mut bytes = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let read = socket.read(&mut buf).await.expect("read request");
            assert!(read > 0, "mock HTTP connection closed before request");
            bytes.extend_from_slice(&buf[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        tx.send(String::from_utf8_lossy(&bytes).to_string())
            .expect("record request");
        let headers = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        socket
            .write_all(headers.as_bytes())
            .await
            .expect("write headers");
        socket.write_all(&body).await.expect("write body");
    });
    (url, requests)
}

pub(super) fn http_body_bounds(bytes: &[u8]) -> Option<(usize, usize)> {
    let body_start = bytes.windows(4).position(|window| window == b"\r\n\r\n")? + 4;
    let headers = std::str::from_utf8(&bytes[..body_start]).ok()?;
    let content_length = headers.lines().find_map(|line| {
        line.strip_prefix("content-length:")
            .or_else(|| line.strip_prefix("Content-Length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
    })?;
    (bytes.len() >= body_start + content_length).then_some((body_start, content_length))
}

#[async_trait]
impl PoiStatusReader for RecordingPoiStatusClient {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        let call_index = {
            let mut calls = self.calls.lock().expect("poi calls");
            let call_index = calls.len();
            calls.push((list_keys.to_vec(), blinded_commitment_datas.to_vec()));
            call_index
        };
        if self
            .fail_calls
            .lock()
            .expect("fail calls")
            .contains(&call_index)
        {
            return Err(PoiError::MerkleRootsRejected);
        }
        let default_status = self
            .default_status
            .lock()
            .expect("default status")
            .unwrap_or(PoiStatus::Valid);
        let statuses = self.statuses.lock().expect("statuses").clone();
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                let status = statuses
                    .get(&data.blinded_commitment)
                    .copied()
                    .unwrap_or(default_status);
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, status))
                        .collect(),
                )
            })
            .collect())
    }
}

pub(super) struct BlockingPoiStatusReader {
    pub(super) started: tokio::sync::Mutex<Option<oneshot::Sender<()>>>,
    pub(super) release: tokio::sync::Mutex<Option<oneshot::Receiver<()>>>,
}

impl BlockingPoiStatusReader {
    pub(super) fn new(started: oneshot::Sender<()>, release: oneshot::Receiver<()>) -> Self {
        Self {
            started: tokio::sync::Mutex::new(Some(started)),
            release: tokio::sync::Mutex::new(Some(release)),
        }
    }
}

#[async_trait]
impl PoiStatusReader for BlockingPoiStatusReader {
    async fn pois_per_list(
        &self,
        _txid_version: &str,
        _chain_type: u8,
        _chain_id: u64,
        list_keys: &[FixedBytes<32>],
        blinded_commitment_datas: &[BlindedCommitmentData],
    ) -> Result<BTreeMap<FixedBytes<32>, BTreeMap<FixedBytes<32>, PoiStatus>>, PoiError> {
        if let Some(started) = self.started.lock().await.take() {
            let _ = started.send(());
        }
        if let Some(release) = self.release.lock().await.take() {
            let _ = release.await;
        }
        Ok(blinded_commitment_datas
            .iter()
            .map(|data| {
                (
                    data.blinded_commitment,
                    list_keys
                        .iter()
                        .copied()
                        .map(|list_key| (list_key, PoiStatus::Valid))
                        .collect(),
                )
            })
            .collect())
    }
}
