use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::net::TcpStream;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;

use crate::error::Error;

pub struct SessionInsert<'a> {
    pub uuid: String,
    pub hash: String,
    pub exp: u64,
    pub permissions: Vec<&'a String>,
    pub server_ws_stream: Option<Arc<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
    pub client_ws_stream: Option<Arc<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
}

#[derive(Debug)]
pub struct Session {
    pub uuid: String,
    pub hash: String,
    pub exp: u64,
    pub permissions: Vec<Arc<String>>,
    pub server_ws_stream: Option<Arc<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
    pub client_ws_stream: Option<Arc<WebSocketStream<MaybeTlsStream<TcpStream>>>>,
}

type Sessions = HashMap<String, Arc<RwLock<Session>>>;

#[derive(Debug)]
pub struct SafeSessions {
    permissions: HashMap<String, Arc<String>>,
    inner: Arc<RwLock<Sessions>>,
}

impl SafeSessions {
    pub fn new(permissions: Vec<&String>) -> Self {
        SafeSessions {
            permissions: permissions
                .iter()
                .map(|p| ((*p).clone(), Arc::new((*p).clone())))
                .collect(),
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn insert<'a>(&self, key: String, value: SessionInsert<'a>) -> Result<(), Error> {
        let mut map = self
            .inner
            .write()
            .map_err(|_e| Error::from("could not lock key set"))?;
        map.insert(
            key,
            Arc::new(RwLock::new(Session {
                permissions: value
                    .permissions
                    .into_iter()
                    .map(|p| self.permissions.get(p).unwrap().clone())
                    .collect(),
                uuid: value.uuid,
                hash: value.hash,
                exp: value.exp,
                server_ws_stream: value.server_ws_stream,
                client_ws_stream: value.client_ws_stream,
            })),
        );
        Ok(())
    }

    pub fn remove(&self, key: &str) -> Result<Option<Arc<RwLock<Session>>>, Error> {
        let mut map = self
            .inner
            .write()
            .map_err(|_e| Error::from("could not lock key set"))?;
        Ok(map.remove(key))
    }

    pub fn get(&self, key: &str) -> Result<Option<Arc<RwLock<Session>>>, Error> {
        let map = self
            .inner
            .read()
            .map_err(|_e| Error::from("could not lock key set"))?;
        Ok(map.get(key).cloned())
    }

    #[allow(dead_code)]
    pub fn get_fun<F, T>(&self, key: &str, callback: F) -> Result<T, Error>
    where
        F: FnOnce(Option<Arc<RwLock<Session>>>) -> Result<T, Error>,
    {
        let map = self
            .inner
            .read()
            .map_err(|_e| Error::from("could not lock key set"))?;
        callback(map.get(key).cloned())
    }

    #[allow(dead_code)]
    pub fn contains_key(&self, key: &str) -> Result<bool, Error> {
        let map = self
            .inner
            .read()
            .map_err(|_e| Error::from("could not lock key set"))?;
        Ok(map.contains_key(key))
    }
}
