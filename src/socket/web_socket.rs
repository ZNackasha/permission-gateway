use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};
use futures::sink::SinkExt;
use futures::stream::StreamExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use hyper_tungstenite::HyperWebsocket;
use tokio::task::JoinHandle;
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
    session: &Arc<RwLock<Session>>,
) -> Result<()> {
    let client_ws_stream = websocket.await?;

    // Connect to the target server
    let (server_ws_stream, _) = tokio_tungstenite::connect_async(&config.sidecar_url).await?;

    let (mut server_write, mut server_read) = server_ws_stream.split();
    let (mut client_write, mut client_read) = client_ws_stream.split();

    let session_inst = session.clone();

    // Forward messages from the client to the server
    let server_to_client: JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut receiver = session_inst
            .read()
            .or(Err(anyhow!("could not read from RWLock")))?
            .get_socket_session()
            .ok_or_else(|| anyhow!("could not get socket session"))?
            .transmitter
            .subscribe();

        loop {
            tokio::select! {
                msg = server_read.next() => {
                if let Some(msg) = msg {
                    let msg = msg?;
                    if session_inst
                    .read()
                    .or(Err(anyhow!("could not read from RWLock")))?
                    .get_access_jwt()
                    .is_expired()
                    {
                        client_write.close().await?;
                        break;
                    }
                    client_write.send(msg).await?;
                }
                },
                _ = receiver.recv() => {
                // Handle receiver event if needed
                    client_write.close().await?;
                    break;
                }
            }
        }
        Ok(())
    });

    let session_inst = session.clone();

    // Forward messages from the server to the client
    let client_to_server: JoinHandle<Result<()>> = tokio::spawn(async move {
        let mut receiver = session_inst
            .read()
            .or(Err(anyhow!("could not read from RWLock")))?
            .get_socket_session()
            .ok_or_else(|| anyhow!("could not get socket session"))?
            .transmitter
            .subscribe();

        loop {
            tokio::select! {
                msg = client_read.next() => {
                    if let Some(msg) = msg {
                        let msg = msg?;
                        if session_inst
                            .read()
                            .or(Err(anyhow!("could not read from RWLock")))?
                            .get_access_jwt()
                            .is_expired()
                        {
                            server_write.close().await?;
                            break;
                        }
                        server_write.send(msg).await?;
                    }
                },
                _ = receiver.recv() => {
                // Handle receiver event if needed
                    server_write.close().await?;
                    break;
                }
            }
        }
        Ok(())
    });

    // Wait for both tasks to complete
    let _ = tokio::try_join!(client_to_server, server_to_client);

    Ok(())
}

fn check_key(
    req: &Request<hyper::body::Incoming>,
    sessions: &Arc<sessions::SafeSessions>,
    config: &Arc<config::Config>,
) -> Result<Arc<std::sync::RwLock<Session>>> {
    sessions
        .get_from_websocket_key(&super::permission::extract_socket_key_from_utl(
            req.uri(),
            &config.socket_encryption_key,
        )?)?
        .ok_or(anyhow!("Key not found"))
}

pub async fn handle_web_socket(
    mut req: Request<hyper::body::Incoming>,
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
