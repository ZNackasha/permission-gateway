use http_body_util::Full;
use hyper::{body::Bytes, Request, Response};
use hyper_util::rt::TokioIo;
use std::{env, sync::Arc};

mod config;
mod error;
mod request;
mod sessions;
mod user;
mod utils;

use crate::error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config: Arc<config::Config> = Arc::new(config::Config {
        listening_address: env::var("LISTENING_ADDRESS").expect("$LISTENING_ADDRESS is not set"),
        iam_url: env::var("IAM_URL").expect("$IAM_URL is not set"),
        encryption_key: env::var("ENCRYPTION_KEY").expect("$ENCRYPTION_KEY is not set"),
        redirect_address: env::var("REDIRECT_ADDRESS").expect("$REDIRECT_ADDRESS is not set"),
        permissions: serde_yaml::from_str(
            &env::var("PERMISSIONS").expect("$PERMISSIONS is not set"),
        )?,
    });

    // This will store the keys and their states
    let keys = Arc::new(sessions::SafeSessions::new(
        config.permissions.iter().map(|(k, _)| k).collect(),
    ));

    let addr: std::net::SocketAddr = config.listening_address.parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Listening on http://{addr}");

    let mut http = hyper::server::conn::http1::Builder::new();
    http.keep_alive(true);

    // let iam_sender = Arc::new(get_iam_sender(config.iam_url.parse()?).await?);

    loop {
        let (stream, _) = listener.accept().await?;
        let keys = keys.clone(); // Clone `keys` before moving it into the closure
        let config = config.clone();
        let connection = http
            .serve_connection(
                TokioIo::new(stream),
                hyper::service::service_fn(move |req| {
                    handle_request(req, keys.clone(), config.clone())
                }),
            )
            .with_upgrades();
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                println!("Error serving HTTP connection: {err:?}");
            }
        });
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    keys: Arc<sessions::SafeSessions>,
    config: Arc<config::Config>,
) -> Result<Response<Full<Bytes>>, Error> {
    if hyper_tungstenite::is_upgrade_request(&req) {
        request::web_socket::handle_web_socket(req, keys, config).await
    } else {
        // Handle non-WebSocket requests

        match (req.method(), req.uri().path()) {
            // Create Key Request
            (&hyper::Method::GET, "/add_key") => {
                request::add_key::handle_add_key(&req, keys, config).await
            }
            _ => Ok(Response::new(Full::new(Bytes::from(
                "Not a WebSocket request",
            )))),
        }
    }
}
