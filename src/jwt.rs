use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::utils;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtPayload {
    pub iss: String, // (issuer): Issuer of the JWT
    pub sub: String, // (subject): Subject of the JWT (the user)
    pub aud: String, // (audience): Recipient for which the JWT is intended

    pub exp: u64, // (expiration time): Time after which the JWT expires
    pub nbf: u64, // (not before time): Time before which the JWT must not be accepted for processing
    pub iat: u64, // (issued at time): Time at which the JWT was issued; can be used to determine age of the JWT

    pub jti: String, // (JWT ID): Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)
}

#[derive(Debug)]
pub struct Jwt {
    payload: JwtPayload,
    full_token: String,
}

impl Jwt {
    pub fn from(token: &str) -> Result<Jwt> {
        let decoding = token.split('.').collect::<Vec<&str>>();

        if decoding.len() != 3 {
            return Err(anyhow!("Invalid token"));
        }
        let payload = &decoding[1];
        let payload = BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| anyhow!("Invalid token"))?;
        let payload: JwtPayload = serde_json::from_slice(&payload)?;
        Ok(Jwt {
            payload,
            full_token: String::from(token),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.payload.exp < utils::get_current_unix_timestamp()
    }

    pub fn get_full_token(&self) -> &str {
        self.full_token.as_str()
    }

    pub fn get_payload(&self) -> &JwtPayload {
        &self.payload
    }
}

// test get_jwt_payload  generate test with token equal to eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzA0NzcxNjQ3LCJpYXQiOjE3MDMyMTcxNjQsImp0aSI6IjRlZWU3YzI3MDM3NjRhMjU4NjY2NmNmYjZjYjUxOGE1IiwidXNlcl9pZCI6MjAxOTQ0LCJpc3MiOiJodHRwczovL3d3dy5iZW56aW5nYS5jb20ifQ.Xm9vSVoPW8itvWQzjCuR5WAjh1De0E6OybC7dQwEyMlavkZa9j5ySVyfUb4nJALuvU7MfihGfYVM01dDGTrREP1YJxfzJZm3f0xwA54QtH6qe4MzN-ADRoecIzzaSzKGohq3XbVGrtZl4uOp0CLTUKGdpXpjieYzSkySqVCjpwigWWZnYg3px6ErhEICvxxaND_2k7QApEwo8ks61mYW6MJ5Bf3sJcgReRupGRPEs1we1d8D1_euiBYdbdBcMgq-wPVqIbbFr3kcTJAh4VuFTawLrechrci6PDFoX-bN3PXjTyocQ1BJ8xFERGKwiJJGtYy958Q156g3_oS5Q5y4SQ
#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_get_jwt_payload() {
        let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzA0NzcxNjQ3LCJpYXQiOjE3MDMyMTcxNjQsImp0aSI6IjRlZWU3YzI3MDM3NjRhMjU4NjY2NmNmYjZjYjUxOGE1IiwidXNlcl9pZCI6MjAxOTQ0LCJpc3MiOiJodHRwczovL3d3dy5iZW56aW5nYS5jb20ifQ.Xm9vSVoPW8itvWQzjCuR5WAjh1De0E6OybC7dQwEyMlavkZa9j5ySVyfUb4nJALuvU7MfihGfYVM01dDGTrREP1YJxfzJZm3f0xwA54QtH6qe4MzN-ADRoecIzzaSzKGohq3XbVGrtZl4uOp0CLTUKGdpXpjieYzSkySqVCjpwigWWZnYg3px6ErhEICvxxaND_2k7QApEwo8ks61mYW6MJ5Bf3sJcgReRupGRPEs1we1d8D1_euiBYdbdBcMgq-wPVqIbbFr3kcTJAh4VuFTawLrechrci6PDFoX-bN3PXjTyocQ1BJ8xFERGKwiJJGtYy958Q156g3_oS5Q5y4SQ";

        let expected_payload = JwtPayload {
            aud: String::from("access"),
            nbf: 1703217164,
            exp: 1704771647,
            iat: 1703217164,
            jti: String::from("4eee7c2703764a2586666cfb6cb518a5"),
            sub: "201944".to_string(),
            iss: String::from("https://www.benzinga.com"),
        };

        let result = Jwt::from(access_token);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().payload, expected_payload);
    }
}
