use axum::{Json, Router, extract::Query, http::StatusCode, response::IntoResponse, routing::get};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::OnceLock,
};

// Load domains.txt into a HashSet using std::sync::OnceLock
static DOMAINS: OnceLock<HashSet<String>> = OnceLock::new();

/// Helper to read domains.txt
fn load_domains(path: &str) -> std::io::Result<HashSet<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let set = reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    Ok(set)
}

#[derive(Debug, Deserialize)]
struct VerifyParams {
    domain: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    domain: String,
    is_disposable: bool,
    reason: Option<String>,
    source: String,
    checked_at: String,
}

async fn verify_handler(Query(params): Query<VerifyParams>) -> impl IntoResponse {
    let domain_orig = params.domain.clone();
    let domain = params.domain.to_lowercase();
    let now = Utc::now().to_rfc3339();

    let set = DOMAINS.get().expect("DOMAINS not initialized");
    let is_disposable = set.contains(&domain);
    let reason = is_disposable.then(|| "Listed as disposable".to_string());

    let resp = VerifyResponse {
        domain: domain_orig,
        is_disposable,
        reason,
        source: "assets/blocklist.txt".into(),
        checked_at: now,
    };

    (StatusCode::OK, Json(resp))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber (logging)
    tracing_subscriber::fmt::init();

    // Resolve path: <current_dir>/assets/blocklist.txt
    let cwd = std::env::current_dir()?;
    let path_buffer = cwd.join("assets").join("blocklist.txt");
    let path = path_buffer.to_str().expect("Path not defined properly");
    
    // Initialize DOMAINS once at startup
    let domains = load_domains(path)?;
    DOMAINS.set(domains).expect("Failed to set domains");

    let port = std::env::var("PORT").unwrap_or("9999".to_string());

    // Build application
    let app = Router::new().route("/v1/domains/verify", get(verify_handler));

    // Run server
    // Run server on localhost:<port>.
    let address = SocketAddr::from((IpAddr::from(Ipv6Addr::UNSPECIFIED), port.parse()?));
    let listener = tokio::net::TcpListener::bind(address).await?;

    tracing::info!("Starting server on {}", address);

    axum::serve(listener, app).await?;

    Ok(())
}
