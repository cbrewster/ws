use std::convert::Infallible;

use anyhow::{anyhow, Result};
use http::{header::CONNECTION, header::UPGRADE, Method, Request, Response, StatusCode};
use hyper::{upgrade::Upgraded, Body};
use sha1::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WS_KEY_APPEND: &'static str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap()
}

async fn handle_upgraded(mut upgraded: Upgraded) -> Result<()> {
    println!("We're doing it!");
    loop {
        let mut header = [0; 2];
        upgraded.read_exact(&mut header).await?;
        let mut payload_len = (header[1] & 0x7F) as usize;
        let has_mask = header[1] & 0x80 == 0x80;

        if payload_len == 126 {
            let mut extended_bytes = [0; 2];
            upgraded.read_exact(&mut extended_bytes).await?;
            payload_len = (extended_bytes[0] as usize) << 8 | (extended_bytes[1] as usize);
        }
        if payload_len == 127 {
            let mut extended_bytes = [0; 8];
            upgraded.read_exact(&mut extended_bytes).await?;
            payload_len = (extended_bytes[0] as usize) << 7 * 8
                | (extended_bytes[1] as usize) << 6 * 8
                | (extended_bytes[2] as usize) << 5 * 8
                | (extended_bytes[3] as usize) << 4 * 8
                | (extended_bytes[4] as usize) << 3 * 8
                | (extended_bytes[5] as usize) << 2 * 8
                | (extended_bytes[6] as usize) << 1 * 8
                | (extended_bytes[7] as usize);
        }

        let mask = if has_mask {
            let mut mask = [0; 4];
            upgraded.read_exact(&mut mask).await?;
            Some(mask)
        } else {
            None
        };

        let mut packet = vec![0; payload_len as usize];
        println!("Payload Length: {}", payload_len);
        upgraded.read_exact(&mut packet).await?;
    }
}

pub async fn web_socket(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    if let Err(e) = handshake(&req) {
        eprintln!("Handshake error: {}", e);
        return Ok(bad_request());
    }

    let accept_key = match compute_accept_key(&req) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Computing Sec-WebSocket-Accept: {}", e);
            return Ok(bad_request());
        }
    };

    println!("Lookin good!");

    tokio::spawn(async move {
        match req.into_body().on_upgrade().await {
            Ok(upgraded) => {
                if let Err(e) = handle_upgraded(upgraded).await {
                    eprintln!("WebSocket error: {}", e);
                }
            }
            Err(e) => eprintln!("Failed to upgrade: {}", e),
        }
    });

    let res = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(Body::empty())
        .expect("failed to build response");

    Ok(res)
}

fn compute_accept_key(req: &Request<Body>) -> Result<String> {
    let req_key = get_header_str(&req, "Sec-WebSocket-Key")?;

    let mut hasher = sha1::Sha1::new();
    hasher.update(format!("{}{}", req_key, WS_KEY_APPEND).as_bytes());

    let sha1 = hasher.finalize();
    Ok(base64::encode(sha1))
}

fn get_header_str<'a, 'b>(req: &'a Request<Body>, key: &'b str) -> Result<&'a str> {
    match req.headers().get(key).map(|v| v.to_str()) {
        Some(Ok(upgrade)) => Ok(upgrade),
        Some(Err(e)) => Err(anyhow!("Reading {} header: {}", key, e)),
        None => Err(anyhow!("Missing {} header", key)),
    }
}

fn handshake(req: &Request<Body>) -> Result<()> {
    // Spec Section 4.2.1

    // Step 1.
    if req.version() < http::Version::HTTP_11 {
        return Err(anyhow!("Invalid HTTP Version"));
    }

    if req.method() != Method::GET {
        return Err(anyhow!("Invalid Method"));
    }

    // TODO: Step 2.

    // Step 3.
    if !get_header_str(req, UPGRADE.as_str())?
        .to_ascii_lowercase()
        .contains("websocket")
    {
        return Err(anyhow!("Upgrade header does not contain websocket"));
    }

    // Step 4.
    if !get_header_str(req, CONNECTION.as_str())?
        .to_ascii_lowercase()
        .contains("upgrade")
    {
        return Err(anyhow!("Connection header does not contain upgrade"));
    }

    // Step 5.
    let ws_key_bytes = match base64::decode(get_header_str(req, "Sec-WebSocket-Key")?) {
        Ok(bytes) => bytes,
        Err(_) => return Err(anyhow!("Failed to base64 decode websocket key")),
    };

    if ws_key_bytes.len() != 16 {
        dbg!(&ws_key_bytes);
        return Err(anyhow!("Sec-WebSocket-Key decoded is not 16 bytes"));
    }

    // Step 6.
    if get_header_str(req, "Sec-WebSocket-Version")? != "13" {
        return Err(anyhow!("Sec-WebSocket-Version is not 13"));
    }

    // TODO: (Optional) Steps 7, 8, 9

    Ok(())
}
