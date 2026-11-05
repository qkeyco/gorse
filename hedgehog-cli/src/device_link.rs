// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2026 QKey Co. Source-available, not open source; commercial use requires a licence. See NOTICE.md.
//! Sign in to activate: get this computer's machine-bound key from gorse.is
//! without copying a machine ID or a key by hand (the device flow `gh auth
//! login` uses). `start` registers this machine and returns a short code and a
//! page to open; the person checks the code and approves while signed in;
//! `wait` polls until the key is ready, which the server hands over once.
//! The device secret is never printed in human output and never stored.
use std::io::Read;
use std::time::{Duration, Instant};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Started {
    pub user_code: String,
    pub verify_url: String,
    pub device_secret: String,
    pub interval: u64,
    pub expires_in: u64,
}

const MAX_RESPONSE: u64 = 64 * 1024;

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .build()
}

fn body(response: ureq::Response) -> Result<serde_json::Value, String> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read the server's answer")?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err("The server's answer was too large".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "The server's answer was not understood".into())
}

fn error_text(value: &serde_json::Value, fallback: &str) -> String {
    value["error"].as_str().unwrap_or(fallback).to_string()
}

pub fn start(machine: &str) -> Result<Started, String> {
    start_at(&crate::api_origin::api_url("/api/device"), machine)
}

fn start_at(url: &str, machine: &str) -> Result<Started, String> {
    let request = serde_json::json!({"action": "start", "machine_id": machine}).to_string();
    match agent()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&request)
    {
        Ok(response) => serde_json::from_value(body(response)?)
            .map_err(|_| "The server's answer was not understood".to_string()),
        Err(ureq::Error::Status(_, response)) => Err(error_text(
            &body(response).unwrap_or_default(),
            "Activation could not start. Please try again.",
        )),
        Err(_) => Err("Cannot reach gorse.is. Check the internet connection and try again.".into()),
    }
}

/// Polls until the key is ready, the code expires, or `deadline` passes.
pub fn wait(secret: &str, deadline: Duration) -> Result<String, String> {
    wait_at(
        &crate::api_origin::api_url("/api/device"),
        secret,
        deadline,
        Duration::from_secs(3),
    )
}

fn wait_at(
    url: &str,
    secret: &str,
    deadline: Duration,
    interval: Duration,
) -> Result<String, String> {
    let until = Instant::now() + deadline;
    let request = serde_json::json!({"action": "poll", "device_secret": secret}).to_string();
    loop {
        let answer = agent()
            .post(url)
            .set("Content-Type", "application/json")
            .send_string(&request);
        match answer {
            Ok(response) if response.status() == 200 => {
                let value = body(response)?;
                return value["license_key"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "The server's answer was not understood".into());
            }
            // 202: still waiting for the person to approve.
            Ok(_) => {}
            Err(ureq::Error::Status(code, response)) if code == 404 || code == 410 => {
                return Err(error_text(
                    &body(response).unwrap_or_default(),
                    "The code expired. Start again.",
                ));
            }
            // Other server or network trouble: keep trying until the deadline.
            Err(_) => {}
        }
        if Instant::now() + interval >= until {
            return Err("The code expired. Start again.".into());
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Serves each canned (status, body) once, in order, and records requests.
    fn serve(answers: Vec<(u16, &'static str)>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/api/device", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for (status, reply) in answers {
                let (mut stream, _) = listener.accept().unwrap();
                // Read the whole request: closing with unread bytes resets the
                // connection before the client sees the answer.
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    request.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&request).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let length = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                    if n == 0 {
                        break;
                    }
                }
                seen.push(String::from_utf8_lossy(&request).to_string());
                let reason = if status == 200 { "OK" } else { "X" };
                write!(stream, "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}", reply.len()).unwrap();
            }
            seen
        });
        (url, handle)
    }

    #[test]
    fn start_sends_the_machine_and_reads_the_code() {
        let (url, server) = serve(vec![(
            200,
            r#"{"user_code":"K7QP-4M2X","verify_url":"https://www.gorse.is/activate?code=K7QP-4M2X","device_secret":"s3cr3t-s3cr3t-s3cr3t-s3cr3t-s3cr3t","interval":3,"expires_in":900}"#,
        )]);
        let started = start_at(&url, "machine-abc").unwrap();
        assert_eq!(started.user_code, "K7QP-4M2X");
        assert_eq!(started.expires_in, 900);
        let seen = server.join().unwrap();
        assert!(seen[0].contains(r#""action":"start""#) && seen[0].contains("machine-abc"));
    }

    #[test]
    fn wait_keeps_polling_while_pending_then_returns_the_key_once() {
        let (url, server) = serve(vec![
            (202, r#"{"status":"pending"}"#),
            (202, r#"{"status":"pending"}"#),
            (
                200,
                r#"{"status":"approved","license_key":"HH1-synthetic"}"#,
            ),
        ]);
        let key = wait_at(
            &url,
            "s3cr3t",
            Duration::from_secs(5),
            Duration::from_millis(10),
        )
        .unwrap();
        assert_eq!(key, "HH1-synthetic");
        assert_eq!(server.join().unwrap().len(), 3);
    }

    #[test]
    fn wait_stops_with_the_servers_reason_when_the_code_expires() {
        let (url, _server) = serve(vec![(
            410,
            r#"{"status":"expired","error":"The code expired. Start again."}"#,
        )]);
        let error = wait_at(
            &url,
            "s3cr3t",
            Duration::from_secs(5),
            Duration::from_millis(10),
        )
        .unwrap_err();
        assert_eq!(error, "The code expired. Start again.");
    }

    #[test]
    fn start_reports_the_servers_refusal() {
        let (url, _server) = serve(vec![(
            503,
            r#"{"error":"Paid activation is not available yet"}"#,
        )]);
        assert_eq!(
            start_at(&url, "m").unwrap_err(),
            "Paid activation is not available yet"
        );
    }
}
