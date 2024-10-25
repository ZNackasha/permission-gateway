use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use std::{env, sync::Arc};

mod config;
mod error;
mod jwt;
mod request;
mod session;
mod sessions;
mod socket;
mod user;
mod utils;

use crate::error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config: Arc<config::Config> = Arc::new(config::Config {
        listening_address: env::var("LISTENING_ADDRESS").expect("$LISTENING_ADDRESS is not set"),

        permission_url: env::var("PERMISSION_URL")
            .expect("$PERMISSION_URL is not set")
            .parse()?,

        socket_encryption_key: env::var("SOCKET_ENCRYPTION_KEY")
            .expect("$SOCKET_ENCRYPTION_KEY is not set"),

        sidecar_url: env::var("SIDECAR_URL")
            .expect("$SIDECAR_URL is not set")
            .parse()?,

        access_token_jwt_cookie_name: env::var("ACCESS_TOKEN_JWT_COOKIE_NAME")
            .expect("$ACCESS_TOKEN_JWT_COOKIE_NAME is not set"),

        refresh_token_jwt_cookie_name: env::var("REFRESH_TOKEN_JWT_COOKIE_NAME")
            .expect("$REFRESH_TOKEN_JWT_COOKIE_NAME is not set"),
    });

    // This will store the keys and their states
    let active_sessions = Arc::new(sessions::SafeSessions::new());

    let addr: std::net::SocketAddr = config.listening_address.parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Listening on http://{addr}");

    let mut http = hyper::server::conn::http1::Builder::new();
    http.keep_alive(true);

    // Create the Hyper client
    let client: hyper_util::client::legacy::Client<_, Full<Bytes>> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();

    loop {
        let (stream, _) = listener.accept().await?;
        let keys = active_sessions.clone(); // Clone `keys` before moving it into the closure
        let config = config.clone();
        let client = client.clone();
        let connection = http
            .serve_connection(
                TokioIo::new(stream),
                hyper::service::service_fn(move |req| {
                    request::handle_request(req, keys.clone(), config.clone(), client.clone())
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
