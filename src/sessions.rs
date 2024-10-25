use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tokio::time::timeout;

use crate::session::Session;
use crate::utils;

type Sessions = HashMap<String, Arc<RwLock<Session>>>;

#[derive(Debug)]
pub struct SafeSessions {
    refresh_token_to_session: Arc<RwLock<Sessions>>,
    socket_key_to_session: Arc<RwLock<Sessions>>,
}

impl SafeSessions {
    pub fn new() -> Self {
        SafeSessions {
            refresh_token_to_session: Arc::new(RwLock::new(HashMap::new())),
            socket_key_to_session: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert<'a>(&self, session: Session) -> Result<Arc<std::sync::RwLock<Session>>> {
        let mut map: std::sync::RwLockWriteGuard<'_, HashMap<String, Arc<RwLock<Session>>>> = self
            .refresh_token_to_session
            .write()
            .map_err(|_e| anyhow!("could not lock key set"))?;

        let token = session.get_refresh_jwt().get_full_token().to_string();
        let session = Arc::new(RwLock::new(session));
        map.insert(token, session.clone());
        Ok(session)
    }

    pub fn remove(&self, session: &Session) -> Result<Option<Arc<RwLock<Session>>>> {
        let mut map = self
            .refresh_token_to_session
            .write()
            .map_err(|_e| anyhow!("could not lock key set"))?;
        Ok(map.remove(session.get_refresh_jwt().get_full_token()))
    }

    pub fn update(&self, mut session: Session) -> Result<Arc<RwLock<Session>>> {
        let mut map = self
            .refresh_token_to_session
            .write()
            .map_err(|_e| anyhow!("could not lock key set"))?;
        let token = session.get_refresh_jwt().get_full_token().to_string();

        if let Some(old_session) = map.get(&token) {
            session.socket_session = old_session
                .read()
                .or(Err(anyhow!("could not read old_session")))?
                .socket_session
                .clone();
        }

        tokio::spawn(async move {
            let _ = timeout(
                Duration::from_secs(
                    session.get_access_jwt().get_payload().exp
                        - utils::get_current_unix_timestamp(),
                ),
                async {
                    if let Some(set) = self.get(&session)? {
                        set.read()
                            .or(Err(anyhow!("could not read session")))?
                            .socket_session
                            .map(|s| {
                                s.transmitter.send("Session expired".to_string()).unwrap();
                            });
                    }
                },
            )
            .await;
        });

        let session = Arc::new(RwLock::new(session));
        map.insert(token, session.clone());
        Ok(session)
    }

    pub fn get(&self, session: &Session) -> Result<Option<Arc<RwLock<Session>>>> {
        let map = self
            .refresh_token_to_session
            .read()
            .map_err(|_e| anyhow!("could not lock key set"))?;

        let token = session.get_refresh_jwt().get_full_token().to_string();
        Ok(map.get(&token).cloned())
    }

    pub fn get_from_websocket_key(&self, key: &str) -> Result<Option<Arc<RwLock<Session>>>> {
        let map = self
            .socket_key_to_session
            .read()
            .map_err(|_e| anyhow!("could not lock key set"))?;
        Ok(map.get(key).cloned())
    }
}
