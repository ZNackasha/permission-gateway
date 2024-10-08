use http_body_util::Full;
use hyper::{body::Bytes, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use jwt::Jwt;
use std::{env, path, sync::Arc};
use tokio_tungstenite::tungstenite::http::uri::Scheme;

mod config;
mod error;
mod jwt;
mod request;
mod sessions;
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

        encryption_key: env::var("ENCRYPTION_KEY").expect("$ENCRYPTION_KEY is not set"),

        sidecar_url: env::var("SIDECAR_URL")
            .expect("$SIDECAR_URL is not set")
            .parse()?,

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
    let cookies = utils::get_cookies(&req);

    // get access tocken from cookies
    let access_token = Jwt::extract_jwt_from_cookies(cookies, &config.jwt_cookie_name.as_str())?;

    if access_token.is_expired() {
        return Err(Error::from("access token expired"));
    }

    if hyper_tungstenite::is_upgrade_request(&req) {
        request::web_socket::handle_web_socket(req, keys, config).await
    } else {
        // Handle non-WebSocket requests

        match (req.method(), req.uri().path()) {
            // Create Key Request
            (&hyper::Method::GET, "/get_websocket_key") => {
                request::add_key::handle_add_key(&req, keys, config).await
            }

            (method, path) => {
                let mut new_req = req.map(|body| body);

                let old_uri = new_req.uri().clone();
                let old_path_and_query = old_uri.path_and_query().unwrap().clone();

                let path = old_path_and_query.path();
                let query = String::from(old_path_and_query.query().unwrap_or_default())
                    .push_str(&format!("permissions={}", keys.join(",")));

                Uri::builder()
                    .scheme(config.sidecar_url.scheme().unwrap_or(&Scheme::HTTP).clone())
                    .authority(config.sidecar_url.authority().unwrap().clone())
                    .path_and_query()
                    .build()
                    .unwrap();
                // old_uri.

                *new_req.uri_mut() = config.sidecar_url.parse().unwrap();
                let mut uri_parts = new_req.uri().clone().into_parts();

                let mut query = uri_parts.query.unwrap_or_default();
                if !query.is_empty() {
                    query.push('&');
                }
                query.push_str(&format!("permissions={}", config.permissions.join(",")));
                uri_parts.query = Some(query);
                *new_req.uri_mut() = http::Uri::from_parts(uri_parts).unwrap();
                match client.request(new_req).await {
                    Ok(response) => Ok(response.map(|body| Full::new(body.into()))),
                    Err(err) => {
                        println!("Error forwarding request: {err:?}");
                        Err(Error::RequestForwardingError)
                    }
                }
            }
        }
    }
}
