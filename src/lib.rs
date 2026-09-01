//! xAI Grok OAuth device flow. Tokens in `$XDG_DATA_HOME/fun/auth.json`.

use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

const XAI_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const XAI_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";
const XAI_DEVICE_URL: &str = "https://auth.x.ai/oauth2/device/code";
const XAI_TOKEN_URL: &str = "https://auth.x.ai/oauth2/token";
const REFRESH_SKEW_MS: u64 = 5 * 60 * 1000;
const MIN_TTL_MS: u64 = 30 * 1000;
const OAUTH_TIMEOUT: Duration = Duration::from_secs(30);

fn auth_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

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

pub fn xdg_data_home() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        if !dir.is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }
    let home = std::env::var("HOME").context("HOME is not set")?;
    if home.is_empty() {
        bail!("HOME is not set");
    }
    Ok(PathBuf::from(home).join(".local/share"))
}

pub fn data_dir() -> Result<PathBuf> {
    Ok(xdg_data_home()?.join("fun"))
}

pub fn auth_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("auth.json"))
}

pub fn has_tokens() -> bool {
    load_tokens_sync().is_some()
}

fn load_tokens_sync() -> Option<OAuthTokens> {
    let Ok(path) = auth_path() else {
        return None;
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return None;
    };
    serde_json::from_str(&text).ok()
}

async fn save_tokens(t: &OAuthTokens) -> Result<()> {
    let path = auth_path()?;
    let dir = path.parent().unwrap_or(Path::new("."));
    tokio::fs::create_dir_all(dir).await.context("auth dir")?;
    let json = serde_json::to_vec_pretty(t).context("encode auth")?;
    let tmp = dir.join(format!(".auth.{}.tmp", std::process::id()));
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let write = async {
        let mut f = opts.open(&tmp).await.context("write auth")?;
        use tokio::io::AsyncWriteExt;
        f.write_all(&json).await.context("write auth")?;
        f.flush().await.context("write auth")?;
        f.sync_all().await.context("write auth")?;
        Ok::<(), anyhow::Error>(())
    };
    if let Err(e) = write.await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    tokio::fs::rename(&tmp, &path)
        .await
        .with_context(|| format!("replace {}", path.display()))
}

async fn load_tokens() -> Option<OAuthTokens> {
    let path = auth_path().ok()?;
    let text = tokio::fs::read_to_string(&path).await.ok()?;
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
    let text = resp.text().await.context("oauth body")?;
    match serde_json::from_str(&text) {
        Ok(v) => Ok((status, v)),
        Err(e) => {
            let preview: String = text.chars().take(200).collect();
            Err(e).context(format!("oauth json (HTTP {status}): {preview}"))
        }
    }
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

#[derive(Debug)]
struct NeedLogin;

impl fmt::Display for NeedLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not logged in — run login")
    }
}

impl std::error::Error for NeedLogin {}

fn need_login() -> anyhow::Error {
    NeedLogin.into()
}

fn oauth_fail(kind: &str, status: u16, body: &TokenBody) -> anyhow::Error {
    let err = body.error.as_deref().unwrap_or("?");
    let desc = body.error_description.as_deref().unwrap_or("");
    anyhow!(format!("xAI {kind} failed (HTTP {status}): {err} {desc}").trim_end().to_string())
}

fn refresh_revoked(body: &TokenBody) -> bool {
    match body.error.as_deref() {
        Some("invalid_grant") | Some("invalid_token") => true,
        _ => {
            let desc = body
                .error_description
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase();
            desc.contains("revoked") || desc.contains("invalid refresh")
        }
    }
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
    let skew = REFRESH_SKEW_MS.min(lifetime_ms.saturating_sub(MIN_TTL_MS));
    Ok(OAuthTokens {
        access: access.into(),
        refresh: refresh.into(),
        expires: now_ms().saturating_add(lifetime_ms).saturating_sub(skew),
    })
}

fn still_fresh(t: &OAuthTokens) -> bool {
    now_ms() < t.expires
}

struct AuthGuard {
    _mem: tokio::sync::MutexGuard<'static, ()>,
    _file: Option<std::fs::File>,
}

fn lock_auth_file() -> Result<Option<std::fs::File>> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let path = data_dir()?.join("auth.lock");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context("auth dir")?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .context("auth lock")?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error()).context("auth lock");
        }
        return Ok(Some(file));
    }
    #[cfg(not(unix))]
    Ok(None)
}

async fn lock_auth() -> Result<AuthGuard> {
    let mem = auth_lock().lock().await;
    let file = tokio::task::spawn_blocking(lock_auth_file)
        .await
        .context("auth lock")??;
    Ok(AuthGuard { _mem: mem, _file: file })
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
        if refresh_revoked(&body) {
            // Another process may have already rotated this grant.
            if let Some(t) = load_tokens().await {
                if t.refresh != refresh {
                    return Ok(t);
                }
                // Keep auth.json. A revoked refresh is not the same as "no login".
                return Err(oauth_fail("refresh", status, &body));
            }
            return Err(need_login());
        }
        return Err(oauth_fail("refresh", status, &body));
    }
    tokens_from_body(&body, Some(refresh))
}

pub fn is_not_logged_in(err: &anyhow::Error) -> bool {
    err.downcast_ref::<NeedLogin>().is_some()
}

/// Access token, refreshing if needed.
pub async fn bearer() -> Result<String> {
    let _guard = lock_auth().await?;
    let mut t = load_tokens().await.ok_or_else(need_login)?;
    if !still_fresh(&t) {
        t = match refresh_tokens(&t.refresh).await {
            Ok(t) => t,
            Err(e) if is_not_logged_in(&e) => return Err(e),
            Err(e) => return Err(e).context("refresh xAI token"),
        };
        save_tokens(&t).await?;
    }
    Ok(t.access)
}

/// Refresh unless `prev_access` was already rotated on disk.
pub async fn force_refresh(prev_access: Option<&str>) -> Result<String> {
    let _guard = lock_auth().await?;
    let t = load_tokens().await.ok_or_else(need_login)?;
    if prev_access.is_some_and(|prev| prev != t.access) {
        return Ok(t.access);
    }
    if still_fresh(&t) {
        // A 401 with a still-fresh access token is not expiry. Rotating
        // here burns the refresh grant and looks like a sudden logout.
        return Ok(t.access);
    }
    let t = match refresh_tokens(&t.refresh).await {
        Ok(t) => t,
        Err(e) if is_not_logged_in(&e) => return Err(e),
        Err(e) => return Err(e).context("refresh xAI token"),
    };
    save_tokens(&t).await?;
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
        let tokens = tokens_from_body(&tok, None)?;
        let _guard = lock_auth().await?;
        save_tokens(&tokens).await?;
        return Ok(Poll::Done);
    }
    Ok(match tok.error.as_deref() {
        Some("authorization_pending") => Poll::Pending,
        Some("slow_down") => {
            Poll::SlowDown(tok.interval.filter(|n| *n > 0).unwrap_or(5))
        }
        Some("access_denied") | Some("authorization_denied") => Poll::Denied,
        Some("expired_token") => Poll::Expired,
        _ => return Err(oauth_fail("token poll", st, &tok)),
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
    let _guard = lock_auth().await?;
    let path = auth_path()?;
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        tokio::fs::remove_file(&path).await.context("remove auth")?;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(error: &str, desc: &str) -> TokenBody {
        TokenBody {
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: Some(error.into()),
            error_description: Some(desc.into()),
            interval: None,
        }
    }

    #[test]
    fn revoked_refresh_is_need_login() {
        assert!(refresh_revoked(&body(
            "invalid_grant",
            "Refresh token has been revoked"
        )));
        assert!(refresh_revoked(&body("invalid_token", "")));
        assert!(!refresh_revoked(&body("expired_token", "")));
        assert!(!refresh_revoked(&body("server_error", "try again")));
        let msg = need_login().to_string();
        assert_eq!(msg, "not logged in — run login");
        let wrapped = oauth_fail("refresh", 400, &body("invalid_grant", "revoked"));
        assert!(wrapped.to_string().contains("invalid_grant"));
        assert!(!wrapped.to_string().contains("TokenBody"));
    }

    #[test]
    fn short_lived_token_stays_fresh() {
        let body = TokenBody {
            access_token: Some("a".into()),
            refresh_token: Some("r".into()),
            expires_in: Some(60),
            error: None,
            error_description: None,
            interval: None,
        };
        let t = tokens_from_body(&body, None).unwrap();
        assert!(still_fresh(&t), "60s token should not look expired immediately");
        assert!(t.expires > now_ms());
        assert!(t.expires - now_ms() >= MIN_TTL_MS - 1);
    }

    #[test]
    fn hour_token_refreshes_with_skew() {
        let body = TokenBody {
            access_token: Some("a".into()),
            refresh_token: Some("r".into()),
            expires_in: Some(3600),
            error: None,
            error_description: None,
            interval: None,
        };
        let t = tokens_from_body(&body, None).unwrap();
        let left = t.expires.saturating_sub(now_ms());
        assert!(left < 3600 * 1000);
        assert!(left > 50 * 60 * 1000);
    }
}
