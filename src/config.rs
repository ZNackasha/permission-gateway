use hyper::Uri;

pub type Permission = String;

pub struct Config {
    pub listening_address: String,

    pub permission_url: Uri,

    pub socket_encryption_key: String,

    pub sidecar_url: Uri,

    pub access_token_jwt_cookie_name: String,
    pub refresh_token_jwt_cookie_name: String,
}
