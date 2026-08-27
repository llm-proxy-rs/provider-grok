use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "provider-grok", about = "xAI Grok device-flow login")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sign in with xAI device flow
    Login,
    /// Delete stored tokens
    Logout,
    /// Show whether tokens exist
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Login => provider_grok::login().await,
        Cmd::Logout => {
            if provider_grok::logout().await? {
                println!("logged out");
            } else {
                println!("not logged in");
            }
            Ok(())
        }
        Cmd::Status => {
            if provider_grok::has_tokens() {
                println!("logged in  ·  {}", provider_grok::auth_path()?.display());
            } else {
                println!("not logged in");
            }
            Ok(())
        }
    }
}
