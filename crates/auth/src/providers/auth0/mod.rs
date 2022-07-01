// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: AGPL-3.0-only

pub mod routes;

use super::super::session::Session;

use std::{fmt, io};

use axum::http::header::{AUTHORIZATION, USER_AGENT};
use axum::http::status::InvalidStatusCode;
use axum::http::StatusCode;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, RedirectUrl, TokenUrl};
use serde::Deserialize;

pub const LOGIN_URI: &str = "/auth/auth0";
pub const LOGOUT_URI: &str = "/auth/auth0/logout";
// pub const AUTHORIZED_URI: &str = "/auth/auth0/authorized";
pub const AUTHORIZED_URI: &str = "/authorized";

#[derive(Debug)]
pub(crate) enum ValidateError {
    Http(ureq::Error),
    Json(io::Error),
    InvalidStatusCode(InvalidStatusCode),
    Auth0(String),
}

impl fmt::Display for ValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "session {}",
            match self {
                ValidateError::Http(e) => format!("HTTP request error: {}", e),
                ValidateError::Json(e) => format!("JSON deserialization error: {}", e),
                ValidateError::InvalidStatusCode(e) => format!("invalid status code: {}", e),
                ValidateError::Auth0(e) => format!("auth0 error: {}", e),
            }
        )
    }
}

impl std::error::Error for ValidateError {}

#[derive(Deserialize)]
pub(crate) struct Auth0User {
    #[serde(rename = "login")]
    pub username: String,
    pub id: u64,
}

//////////////////////// TODO
pub(crate) async fn validate(session: &Session) -> Result<Auth0User, ValidateError> {
    #[derive(Deserialize)]
    struct Error {
        message: String,
    }

    let res = ureq::get("https://api.github.com/user")
        .set(USER_AGENT.as_str(), "benefice")
        .set(
            AUTHORIZATION.as_str(),
            &format!("Bearer {}", session.token.secret()),
        )
        .call()
        .map_err(ValidateError::Http)?;
    match StatusCode::from_u16(res.status()) {
        Ok(s) if s.is_success() => res.into_json().map_err(ValidateError::Json),
        Ok(_) => res
            .into_json()
            .map_err(ValidateError::Json)
            .and_then(|Error { message }| Err(ValidateError::Auth0(message))),
        Err(e) => Err(ValidateError::InvalidStatusCode(e)),
    }
}

#[derive(Clone)]
pub struct OAuthClient(pub BasicClient);

impl OAuthClient {
    pub fn new(host: &str, auth0_host: &str, client_id: String) -> OAuthClient {
        let auth_url = format!("https://{}/authorize", auth0_host);
        let token_url = format!("https://{}/oauth/token", auth0_host);

        OAuthClient(
            BasicClient::new(
                ClientId::new(client_id),
                None,
                AuthUrl::new(auth_url).unwrap(),
                Some(TokenUrl::new(token_url).unwrap()),
            )
            .set_redirect_uri(
                RedirectUrl::new(format!("http://{}{}", host, AUTHORIZED_URI)).unwrap(),
            ),
        )
    }
}
