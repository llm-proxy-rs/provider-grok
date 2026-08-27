//! xAI Grok OAuth device flow. Tokens in `$XDG_DATA_HOME/provider-grok/auth.json`.

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const XAI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const XAI_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";
const XAI_DEVICE_URL: &str = "https://auth.x.ai/oauth2/device/code";
const XAI_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
const REFRESH_SKEW_MS: u64 = 5 * 60 * 1000;
const OAUTH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuthTokens {
    pub access: String,
    pub refresh: String,
    pub expires: u64,
}

#[derive(Debug, Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: Option<String>,
    interval: Option<u64>,
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TokenBody {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    error: Option<String>,
    error_description: Option<String>,
    interval: Option<u64>,
}

#[derive(Clone)]
pub struct DeviceStart {
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub device_code: String,
    pub interval: u64,
    pub deadline_ms: u64,
}

pub enum Poll {
    Pending,
    SlowDown(u64),
    Done,
    Denied,
    Expired,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir).join("provider-grok"));
        }
    }
    let home = std::env::var("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".local/share/provider-grok"))
}

pub fn auth_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("auth.json"))
}

pub fn has_tokens() -> bool {
    auth_path()
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| serde_json::from_str::<OAuthTokens>(&t).ok())
        .is_some()
}

async fn save_tokens(t: &OAuthTokens) -> Result<()> {
    let path = auth_path()?;
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await.context("auth dir")?;
    }
    let json = serde_json::to_vec_pretty(t).context("encode auth")?;
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).await.context("write auth")?;
    use tokio::io::AsyncWriteExt;
    f.write_all(&json).await.context("write auth")?;
    f.flush().await.context("write auth")?;
    Ok(())
}

async fn load_tokens() -> Option<OAuthTokens> {
    if let Ok(path) = auth_path() {
        if let Ok(text) = tokio::fs::read_to_string(&path).await {
            if let Ok(t) = serde_json::from_str(&text) {
                return Some(t);
            }
        }
    }
    // reuse a prior coding-agent login if present
    let fallback = std::env::var("HOME").ok().map(|h| {
        PathBuf::from(h).join(".local/share/coding-agent/auth.json")
    })?;
    let text = tokio::fs::read_to_string(fallback).await.ok()?;
    serde_json::from_str(&text).ok()
}

async fn post_form<T: DeserializeOwned>(url: &str, fields: &[(&str, &str)]) -> Result<(u16, T)> {
    let resp = reqwest::Client::builder()
        .timeout(OAUTH_TIMEOUT)
        .build()
        .context("oauth client")?
        .post(url)
        .header("Accept", "application/json")
        .form(fields)
        .send()
        .await
        .context("oauth request")?;
    let status = resp.status().as_u16();
    let v = resp.json().await.context("oauth json")?;
    Ok((status, v))
}

fn https_only(raw: &str) -> Result<String> {
    if raw.contains(char::is_whitespace) {
        bail!("untrusted verification URI");
    }
    let url = reqwest::Url::parse(raw).context("verification URI")?;
    let host = url.host_str().unwrap_or("");
    let xai = host == "x.ai" || host.ends_with(".x.ai");
    if url.scheme() != "https" || !xai {
        bail!("untrusted verification URI ({host})");
    }
    Ok(raw.into())
}

fn tokens_from_body(body: &TokenBody, prev_refresh: Option<&str>) -> Result<OAuthTokens> {
    let access = body
        .access_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("oauth missing access_token"))?;
    let refresh = body
        .refresh_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .or(prev_refresh)
        .ok_or_else(|| anyhow!("oauth missing refresh_token"))?;
    let lifetime_ms = body.expires_in.unwrap_or(3600).saturating_mul(1000);
    Ok(OAuthTokens {
        access: access.into(),
        refresh: refresh.into(),
        expires: now_ms()
            .saturating_add(lifetime_ms)
            .saturating_sub(REFRESH_SKEW_MS),
    })
}

async fn refresh_tokens(refresh: &str) -> Result<OAuthTokens> {
    let (status, body) = post_form(
        XAI_TOKEN_URL,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", XAI_CLIENT_ID),
            ("refresh_token", refresh),
        ],
    )
    .await?;
    if !(200..300).contains(&status) {
        bail!("xAI refresh failed (HTTP {status}): {body:?}");
    }
    tokens_from_body(&body, Some(refresh))
}

/// Access token, refreshing if needed.
pub async fn bearer() -> Result<String> {
    let mut t = load_tokens().await.context("not logged in — run login")?;
    if now_ms() >= t.expires {
        t = refresh_tokens(&t.refresh)
            .await
            .context("refresh xAI token")?;
        save_tokens(&t).await?;
    }
    Ok(t.access)
}

pub async fn start_login() -> Result<DeviceStart> {
    let (status, body): (_, DeviceCode) = post_form(
        XAI_DEVICE_URL,
        &[
            ("client_id", XAI_CLIENT_ID),
            ("scope", XAI_SCOPE),
            ("referrer", "connect"),
        ],
    )
    .await?;
    if !(200..300).contains(&status) {
        bail!("xAI device auth failed (HTTP {status}): {body:?}");
    }
    let uri = https_only(&body.verification_uri)?;
    let open_uri = body
        .verification_uri_complete
        .as_deref()
        .and_then(|u| https_only(u).ok())
        .unwrap_or_else(|| uri.clone());
    let interval = body.interval.filter(|n| *n > 0).unwrap_or(5);
    let expires_in = body.expires_in.unwrap_or(900);
    Ok(DeviceStart {
        user_code: body.user_code,
        verification_uri: uri,
        verification_uri_complete: open_uri,
        device_code: body.device_code,
        interval,
        deadline_ms: now_ms().saturating_add(expires_in.saturating_mul(1000)),
    })
}

pub async fn poll_token(device_code: &str) -> Result<Poll> {
    let (st, tok): (_, TokenBody) = post_form(
        XAI_TOKEN_URL,
        &[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", XAI_CLIENT_ID),
            ("device_code", device_code),
        ],
    )
    .await?;
    if (200..300).contains(&st) {
        save_tokens(&tokens_from_body(&tok, None)?).await?;
        return Ok(Poll::Done);
    }
    Ok(match tok.error.as_deref() {
        Some("authorization_pending") => Poll::Pending,
        Some("slow_down") => {
            Poll::SlowDown(tok.interval.filter(|n| *n > 0).unwrap_or(5))
        }
        Some("access_denied") | Some("authorization_denied") => Poll::Denied,
        Some("expired_token") => Poll::Expired,
        other => {
            let desc = tok.error_description.as_deref().unwrap_or("");
            bail!(
                "xAI token poll failed (HTTP {st}): {} {desc}",
                other.unwrap_or("?")
            )
        }
    })
}

/// CLI device flow: print URL, open browser, poll until done.
pub async fn login() -> Result<()> {
    let d = start_login().await?;
    println!("Sign in with SuperGrok or X Premium");
    println!("Visit {}", d.verification_uri);
    println!("Enter code: {}", d.user_code);
    let _ = tokio::process::Command::new("xdg-open")
        .arg(&d.verification_uri_complete)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut interval = d.interval;
    tokio::time::sleep(Duration::from_secs(interval)).await;
    loop {
        if now_ms() >= d.deadline_ms {
            bail!("device flow timed out");
        }
        match poll_token(&d.device_code).await? {
            Poll::Done => {
                println!("logged in  ·  {}", auth_path()?.display());
                return Ok(());
            }
            Poll::Pending => {}
            Poll::SlowDown(n) => interval = n,
            Poll::Denied => bail!("xAI device authorization was denied"),
            Poll::Expired => bail!("xAI device code expired"),
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

pub async fn logout() -> Result<bool> {
    let path = auth_path()?;
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        tokio::fs::remove_file(&path).await.context("remove auth")?;
        Ok(true)
    } else {
        Ok(false)
    }
}
