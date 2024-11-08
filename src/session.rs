use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use crate::jwt::Jwt;

#[derive(Debug)]
pub struct SocketSession {
    pub uuid: String,
    pub hash: String,
    pub transmitter: tokio::sync::broadcast::Sender<String>,
    // pub socket_streams: Vec<Arc<Mutex<SocketStreams>>>,
}

#[derive(Debug)]
pub struct Session {
    refresh_jwt: Jwt,
    access_jwt: Jwt,
    permissions: Vec<Arc<String>>,
    socket_session: Option<Arc<SocketSession>>,
}

lazy_static::lazy_static! {
    static ref GLOBAL_STRINGS: RwLock<HashMap<String, Arc<String>>> = RwLock::new(HashMap::new());
}

impl Session {
    pub fn new(refresh_jwt: Jwt, access_jwt: Jwt) -> Self {
        Session {
            refresh_jwt,
            access_jwt,
            permissions: vec![],
            socket_session: None,
        }
    }

    pub fn from_cookies<'a>(
        cookies: impl Iterator<Item = &'a str>,
        access_jwt_cookie_name: &str,
        refresh_jwt_cookie_name: &str,
    ) -> Result<Session> {
        let mut access_jwt = None;
        let mut refresh_jwt = None;

        for cookie in cookies {
            if cookie.starts_with(access_jwt_cookie_name) {
                if let Some(value) = cookie.get(access_jwt_cookie_name.len()..) {
                    if value.starts_with('=') {
                        access_jwt = Some(Jwt::from(&value[1..])?);
                        if access_jwt.is_some() && refresh_jwt.is_some() {
                            break;
                        }
                    }
                }
            } else if cookie.starts_with(refresh_jwt_cookie_name) {
                if let Some(value) = cookie.get(refresh_jwt_cookie_name.len()..) {
                    if value.starts_with('=') {
                        refresh_jwt = Some(Jwt::from(&value[1..])?);
                        if access_jwt.is_some() && refresh_jwt.is_some() {
                            break;
                        }
                    }
                }
            }
        }

        let access_jwt = if let Some(token) = access_jwt {
            token
        } else {
            return Err(anyhow!("access token not found"));
        };

        let refresh_jwt = if let Some(token) = refresh_jwt {
            token
        } else {
            return Err(anyhow!("refresh token not found"));
        };

        if access_jwt.is_expired() {
            return Err(anyhow!("access token expired"));
        }

        if refresh_jwt.is_expired() {
            return Err(anyhow!("access token expired"));
        }

        Ok(Session::new(refresh_jwt, access_jwt))
    }

    pub fn set_socket_session(&mut self, uuid: String, hash: String) {
        let (tx, _) = tokio::sync::broadcast::channel(16);
        let socket_session = SocketSession {
            uuid,
            hash,
            transmitter: tx,
        };
        self.socket_session = Some(Arc::new(socket_session));
    }

    pub fn update_socket_session(&mut self, socket_session: &Arc<SocketSession>) {
        self.socket_session = Some(socket_session.clone());
    }

    fn get_or_insert_arc_string(value: &str) -> Arc<String> {
        {
            let global_strings = GLOBAL_STRINGS.read().unwrap();
            if let Some(arc_string) = global_strings.get(value) {
                return arc_string.clone();
            }
        }

        let mut global_strings = GLOBAL_STRINGS.write().unwrap();
        global_strings
            .entry(value.to_string())
            .or_insert_with(|| Arc::new(value.to_string()))
            .clone()
    }

    pub fn set_permissions(&mut self, permissions: Vec<String>) {
        self.permissions = permissions
            .into_iter()
            .map(|s| Session::get_or_insert_arc_string(s.as_str()))
            .collect()
    }

    pub fn get_permissions(&self) -> Vec<Arc<String>> {
        self.permissions.clone()
    }

    pub fn get_access_jwt(&self) -> &Jwt {
        &self.access_jwt
    }

    pub fn get_refresh_jwt(&self) -> &Jwt {
        &self.refresh_jwt
    }

    pub fn get_socket_session(&self) -> Option<&Arc<SocketSession>> {
        self.socket_session.as_ref()
    }
}
