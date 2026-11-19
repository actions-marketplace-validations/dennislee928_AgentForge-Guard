//! A mock of packages/cloudflare-adapter for contract tests (T11.5). It
//! applies the same checks as the Worker: the HMAC signature over the raw
//! body, the protocol fields, and unpacking the tar archive. It records
//! every request so tests can inspect exactly what afg sent.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{KeyInit, Mac};

#[derive(Debug, Clone)]
pub struct Received {
    pub path: String,
    pub signature_ok: bool,
    pub body: serde_json::Value,
    /// Paths in the uploaded archive.
    pub files: Vec<String>,
}

pub struct MockWorker {
    pub url: String,
    pub received: Arc<Mutex<Vec<Received>>>,
}

fn verify(key: &[u8], body: &[u8], header: &str) -> bool {
    let Some(hex) = header.strip_prefix("v1=") else {
        return false;
    };
    let Ok(tag) = (0..hex.len())
        .step_by(2)
        .map(|i| {
            hex.get(i..i + 2)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or(())
    else {
        return false;
    };
    let mut m = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key).unwrap();
    m.update(body);
    m.verify_slice(&tag).is_ok()
}

impl MockWorker {
    /// Serve until the test process exits. `exit_code` is returned for every
    /// execute request; stdout echoes the archive's file list.
    pub fn start(key: Vec<u8>, exit_code: i32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let rec = received.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                let (mut len, mut sig) = (0usize, String::new());
                loop {
                    let mut h = String::new();
                    reader.read_line(&mut h).unwrap();
                    let h = h.trim_end();
                    if h.is_empty() {
                        break;
                    }
                    let (k, v) = h.split_once(':').unwrap_or((h, ""));
                    match k.to_ascii_lowercase().as_str() {
                        "content-length" => len = v.trim().parse().unwrap(),
                        "x-afg-signature" => sig = v.trim().to_owned(),
                        _ => {}
                    }
                }
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                let signature_ok = verify(&key, &body, &sig);
                let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                let mut files = Vec::new();
                if let Some(a) = json["archive"].as_str() {
                    let bytes = B64.decode(a).unwrap();
                    let mut ar = tar::Archive::new(&bytes[..]);
                    for e in ar.entries().unwrap() {
                        let e = e.unwrap();
                        if e.header().entry_type().is_file() {
                            files.push(e.path().unwrap().display().to_string());
                        }
                    }
                    files.sort();
                }
                rec.lock().unwrap().push(Received {
                    path: path.clone(),
                    signature_ok,
                    body: json.clone(),
                    files: files.clone(),
                });
                let (status, resp) = if !signature_ok {
                    (
                        "401 Unauthorized",
                        serde_json::json!({"error": "bad signature"}),
                    )
                } else if path == "/v1/cleanup" {
                    (
                        "200 OK",
                        serde_json::json!({"id": json["id"], "cleaned": true}),
                    )
                } else {
                    let out = format!("{}\n", files.join("\n"));
                    let digest = {
                        use sha2::Digest;
                        let d = sha2::Sha256::digest(out.as_bytes());
                        format!(
                            "sha256:{}",
                            d.iter().map(|b| format!("{b:02x}")).collect::<String>()
                        )
                    };
                    (
                        "200 OK",
                        serde_json::json!({
                            "id": json["id"], "exitCode": exit_code, "timedOut": false, "durationMs": 5,
                            "stdout": {"data": B64.encode(out.as_bytes()), "len": out.len(), "truncated": false, "sha256": digest},
                            "stderr": {"data": "", "len": 0, "truncated": false, "sha256": "sha256:e3b0"},
                            "manifestHash": json["manifestHash"],
                        }),
                    )
                };
                let text = resp.to_string();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        Self { url, received }
    }

    pub fn requests(&self) -> Vec<Received> {
        self.received.lock().unwrap().clone()
    }
}
