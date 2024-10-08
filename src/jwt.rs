use std::cell::RefCell;

use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde::{Deserialize, Serialize};

use crate::utils;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct JwtPayload {
    pub token_type: String,
    pub exp: u64,
    pub iat: u64,
    pub jti: String,
    pub user_id: i32,
    pub iss: String,
}

pub struct Jwt<'a> {
    payload: JwtPayload,
    full_token: &'a str,
}

thread_local! {
  static STARTS_WITH_COOKIE: RefCell<Option<String>> = RefCell::new(None);
}

impl<'a> Jwt<'a> {
    pub fn from(token: &'a str) -> Result<Jwt<'a>> {
        let sub_token = token.split('.').collect::<Vec<&str>>();
        if sub_token.len() != 3 {
            return Err(anyhow!("Invalid token"));
        }
        let payload = sub_token[1];
        let payload = BASE64_URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| anyhow!("Invalid token"))?;
        let payload: JwtPayload = serde_json::from_slice(&payload)?;
        Ok(Jwt {
            payload,
            full_token: token,
        })
    }

    pub fn extract_jwt_from_cookies(
        cookies: impl Iterator<Item = &'a str>,
        jwt_cookie_name: &str,
    ) -> Result<Jwt<'a>> {
        STARTS_WITH_COOKIE.with(|cookie| {
            if cookie.borrow().is_none() {
                *cookie.borrow_mut() = Some(format!("{}=", jwt_cookie_name));
            }
            Self::from(
                cookies
                    .into_iter()
                    .find(|x| x.starts_with(cookie.borrow().as_ref().unwrap().as_str()))
                    .map_or(None, |x| x.split('=').nth(1))
                    .ok_or(anyhow!("No key found"))?,
            )
        })
    }

    pub fn is_expired(&self) -> bool {
        self.payload.exp < utils::get_current_unix_timestamp()
    }

    pub fn get_full_token(&self) -> &str {
        self.full_token
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
            token_type: String::from("access"),
            exp: 1704771647,
            iat: 1703217164,
            jti: String::from("4eee7c2703764a2586666cfb6cb518a5"),
            user_id: 201944,
            iss: String::from("https://www.benzinga.com"),
        };

        let result = Jwt::from(access_token);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().payload, expected_payload);
    }
}
