use std::sync::Arc;

use futures::sink::SinkExt;
use futures::stream::StreamExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use hyper_tungstenite::HyperWebsocket;
use tokio_tungstenite::tungstenite::Message;

use crate::error::Error;
use crate::{config, sessions};

async fn close_socket(websocket: HyperWebsocket, err: Option<Error>) -> Result<(), Error> {
    let mut ws = websocket.await?;
    if let Some(err) = err {
        ws.send(Message::Text(err.to_string())).await?;
    }
    ws.close(None).await?;
    Ok(())
}

async fn serve_websocket(
    websocket: HyperWebsocket,
    config: Arc<config::Config>,
) -> Result<(), Error> {
    let client_ws_stream = websocket.await?;

    // Connect to the target server
    let (server_ws_stream, _) = tokio_tungstenite::connect_async(&config.redirect_address)
        .await
        .unwrap();
    let (mut server_write, mut server_read) = server_ws_stream.split();
    let (mut client_write, mut client_read) = client_ws_stream.split();

    // Forward messages from the client to the server
    let server_to_client = tokio::spawn(async move {
        while let Some(msg) = server_read.next().await {
            let msg = msg.unwrap();
            client_write.send(msg).await.unwrap();
        }
    });

    // Forward messages from the server to the client
    let client_to_server = tokio::spawn(async move {
        while let Some(msg) = client_read.next().await {
            let msg = msg.unwrap();
            server_write.send(msg).await.unwrap();
        }
    });

    // Wait for both tasks to complete
    let _ = tokio::try_join!(client_to_server, server_to_client);
    Ok(())
}

pub async fn handle_web_socket(
    mut req: Request<hyper::body::Incoming>,
    keys: Arc<sessions::SafeSessions>,
    config: Arc<config::Config>,
) -> Result<Response<Full<Bytes>>, Error> {
    // Upgrade the connection to a WebSocket connection

    // Spawn a new task to handle the WebSocket connection
    let (response, websocket) = hyper_tungstenite::upgrade(&mut req, None)?;
    tokio::spawn(async move {
        if let Err(err) = super::utils::request_has_valid_key(&req, keys, &config.encryption_key) {
            if let Err(e) = close_socket(websocket, Some(err)).await {
                eprintln!("Error closing websocket connection: {e}");
            }
        } else if let Err(e) = serve_websocket(websocket, config).await {
            eprintln!("Error in websocket connection: {e}");
        }
    });
    Ok(response)
}
