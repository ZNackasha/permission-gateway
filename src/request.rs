use anyhow::{anyhow, Result};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, Response, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use std::{
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::http::uri::Scheme;

use crate::{config, session::Session, sessions, socket, user, utils};

async fn set_timer(session: Arc<RwLock<Session>>, active_sessions: Arc<sessions::SafeSessions>) {
    let timeout = timeout(
        match session.clone().read() {
            Ok(session) => Duration::from_secs(
                session.get_access_jwt().get_payload().exp - utils::get_current_unix_timestamp(),
            ),
            Err(_) => {
                eprintln!("Error reading session");
                Duration::from_secs(0)
            }
        },
        async move {
            match session.read() {
                Ok(session) => match active_sessions.get(&session) {
                    Ok(Some(set)) => {
                        if let Ok(session) = set.read() {
                            if session.get_access_jwt().is_expired() {
                                if let Some(socket_session) = session.get_socket_session() {
                                    socket_session
                                        .transmitter
                                        .send("Session expired".to_string())
                                        .unwrap();
                                    match active_sessions.remove(&session) {
                                        Ok(_) => (),
                                        Err(_) => eprintln!("Error removing session"),
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => (),
                    Err(e) => eprintln!("Error getting session: {:?}", e),
                },
                Err(e) => eprintln!("Error reading session: {:?}", e),
            }
        },
    );

    tokio::spawn(async move {
        match timeout.await {
            Ok(_) => (),
            Err(_) => eprintln!("Error setting timer"),
        }
    });
}

pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    active_sessions: Arc<sessions::SafeSessions>,
    config: Arc<config::Config>,
    client: hyper_util::client::legacy::Client<HttpConnector, Full<Bytes>>,
) -> Result<Response<Full<Bytes>>> {
    let cookies = utils::get_cookies(&req);

    // get access tocken from cookies
    let mut session = Session::from_cookies(
        cookies,
        &config.access_token_jwt_cookie_name,
        &config.refresh_token_jwt_cookie_name,
    )?;

    let session = match active_sessions.get(&session)? {
        None => {
            let permissions = user::get_user_permissions(&session, &config).await?;
            session.set_permissions(permissions);
            let session = active_sessions.insert(session)?;
            set_timer(session.clone(), active_sessions.clone()).await;
            session
        }
        Some(cur_session) => {
            if cur_session
                .read()
                .map_err(|_| anyhow!("Session mismatch"))?
                .get_access_jwt()
                .is_expired()
            {
                let permissions = user::get_user_permissions(&session, &config).await?;
                session.set_permissions(permissions);
                let session = active_sessions.update(session)?.clone();
                set_timer(session.clone(), active_sessions.clone()).await;
                session
            } else {
                cur_session.clone()
            }
        }
    };

    if hyper_tungstenite::is_upgrade_request(&req) {
        socket::web_socket::handle_web_socket(req, &active_sessions, &config).await
    } else {
        // Handle non-WebSocket requests

        match (req.method(), req.uri().path()) {
            // Create Key Request
            (&hyper::Method::GET, "/get_websocket_key") => {
                socket::gen_socket_key::gen_socket_key(&session, &config)
            }

            (&hyper::Method::GET, "/socket_keep_alive") => {
                socket::gen_socket_key::gen_socket_key(&session, &config)
            }

            (_, _) => {
                let old_uri = req.uri().clone();
                let old_path_and_query = old_uri.path_and_query().unwrap().clone();

                let path = old_path_and_query.path();
                let mut query = String::from(old_path_and_query.query().unwrap_or_default());
                query.push_str(&format!(
                    "permissions={}",
                    session
                        .read()
                        .unwrap()
                        .get_permissions()
                        .iter()
                        .map(|arc_str| arc_str.as_str())
                        .collect::<Vec<&str>>()
                        .join(",")
                ));

                let new_uri = Uri::builder()
                    .scheme(config.sidecar_url.scheme().unwrap_or(&Scheme::HTTP).clone())
                    .authority(config.sidecar_url.authority().unwrap().clone())
                    .path_and_query(format!("{}?{}", path, query))
                    .build()
                    .unwrap();

                let (mut parts, body) = req.into_parts();
                parts.uri = new_uri.clone();
                let body = body.collect().await?.to_bytes();
                let req = Request::from_parts(parts, Full::from(body));

                match client.request(req).await {
                    Ok(response) => {
                        let (parts, body) = response.into_parts();
                        let body = body.collect().await?.to_bytes();
                        Ok(Response::from_parts(parts, Full::from(body)))
                    }
                    Err(err) => {
                        println!("Error forwarding request: {err:?}");
                        return Err(anyhow!(err));
                    }
                }
            }
        }
    }
}
