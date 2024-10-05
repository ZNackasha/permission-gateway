use hyper::{header, Request};
use sha256::digest;
use uuid::Uuid;

pub fn get_cookies(req: &Request<hyper::body::Incoming>) -> impl Iterator<Item = &str> {
    req.headers()
        .get_all(header::COOKIE)
        .iter()
        .flat_map(|x| x.to_str().unwrap_or("").split(';'))
}

pub fn generate_uuid() -> String {
    let uuid = Uuid::new_v4();
    uuid.to_string()
}

pub fn cypher_hash_string(text: &str, key: &str) -> String {
    digest(String::from(text) + "." + key)
}

pub fn get_current_unix_timestamp() -> u64 {
    let start = std::time::SystemTime::now();
    let since_the_epoch = start
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs()
}
