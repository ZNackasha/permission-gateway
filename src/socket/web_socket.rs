use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use hyper_tungstenite::HyperWebsocket;
use tokio_tungstenite::tungstenite::Message;

use crate::session::Session;
use crate::{config, sessions};

async fn close_socket(websocket: HyperWebsocket, err: Option<anyhow::Error>) -> Result<()> {
    let mut ws = websocket.await?;
    if let Some(err) = err {
        ws.send(Message::Text(err.to_string())).await?;
    }
    ws.close(None).await?;
    Ok(())
}

async fn serve_websocket(
    websocket: HyperWebsocket,
    config: &Arc<config::Config>,
    session: &Arc<Mutex<Session>>,
) -> Result<()> {
    let client_ws_stream = websocket.await?;

    // Connect to the target server
    let (server_ws_stream, _) = tokio_tungstenite::connect_async(&config.sidecar_url).await?;

    let (mut server_write, mut server_read) = server_ws_stream.split();
    let (mut client_write, mut client_read) = client_ws_stream.split();

    let session2 = session.clone();

    // Forward messages from the client to the server
    let server_to_client = tokio::spawn(async move {
        while let Some(msg) = server_read.next().await {
            let msg = msg.unwrap();
            if session2
                .lock()
                .or(Err(anyhow!("could not read from RWLock")))?
                .access_jwt
                .is_expired()
            {
                client_write.close().await?;
                break;
            }
            client_write.send(msg).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let session = session.clone();

    // Forward messages from the server to the client
    let client_to_server = tokio::spawn(async move {
        while let Some(msg) = client_read.next().await {
            let msg = msg.unwrap();
            if session
                .clone()
                .lock()
                .or(Err(anyhow!("could not read from RWLock")))?
                .access_jwt
                .is_expired()
            {
                server_write.close().await?;
                break;
            }
            server_write.send(msg).await?;
        }
        Ok::<(), anyhow::Error>(())
    });

    // Run both tasks concurrently
    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

fn check_key(
    req: &Request<hyper::body::Incoming>,
    sessions: &Arc<sessions::SafeSessions>,
    config: &Arc<config::Config>,
) -> Result<Arc<Mutex<Session>>> {
    sessions
        .get_from_websocket_key(&super::permission::extract_socket_key_from_utl(
            req.uri(),
            &config.socket_encryption_key,
        )?)?
        .ok_or(anyhow!("Key not found"))
}

pub async fn handle_web_socket(
    req: Request<hyper::body::Incoming>,
    sessions: &Arc<sessions::SafeSessions>,
    config: &Arc<config::Config>,
) -> Result<Response<Full<Bytes>>> {
    // Upgrade the connection to a WebSocket connection

    // Spawn a new task to handle the WebSocket connection

    let sessions = sessions.clone();
    let config = config.clone();
    let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)?;
    tokio::spawn(async move {
        match check_key(&req, &sessions, &config) {
            Ok(session) => {
                if let Err(e) = serve_websocket(websocket, &config, &session).await {
                    Err(anyhow!("Error closing websocket connection: {e}"))?;
                }
            }
            Err(e) => {
                if let Err(e) = close_socket(websocket, Some(e)).await {
                    Err(anyhow!("Error closing websocket connection: {e}"))?;
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    });
    Ok(response)
}
