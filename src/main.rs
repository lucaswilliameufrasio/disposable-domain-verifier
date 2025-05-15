use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, Uri},
    response::IntoResponse,
    routing::get,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader},
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

/// Helper to read domains.txt
fn load_domains(path: &str) -> std::io::Result<HashSet<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let set = reader
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_lowercase())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    Ok(set)
}

#[derive(Clone)]
struct AppState {
    domains: HashSet<String>,
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
    let state = AppState { domains };

    let port = std::env::var("PORT").unwrap_or("9999".to_string());

    // Build application
    let app = Router::new()
        .route("/v1/domains/verify", get(verify_handler))
        .layer(
            tower_http::trace::TraceLayer::new_for_http()
                .make_span_with(|req: &axum::extract::Request<_>| {
                    let ip = req
                        .headers()
                        .get("x-forwarded-for")
                        .and_then(|header_value| header_value.to_str().ok())
                        .and_then(|header_value| {
                            header_value
                                .split(',')
                                .next()
                                .map(str::trim)
                                .map(str::to_string)
                        })
                        .or_else(|| {
                            req.extensions()
                                .get::<axum::extract::ConnectInfo<SocketAddr>>()
                                .map(|ci| ci.0.ip().to_string())
                        })
                        .unwrap_or_else(|| "unknown".into());

                    tracing::info_span!(
                        "http-request",
                        %ip,
                        method = %req.method(),
                        path = %req.uri().path(),
                        level = %tracing::Level::INFO
                    )
                })
                .on_response(
                    tower_http::trace::DefaultOnResponse::new().level(tracing::Level::INFO),
                ),
        )
        .with_state(state)
        .fallback(fallback_handler);

    // Run server on localhost:<port>
    let address = SocketAddr::from((IpAddr::from(Ipv6Addr::UNSPECIFIED), port.parse()?));
    let listener = tokio::net::TcpListener::bind(address).await?;

    tracing::info!("Starting server on {}", address);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn fallback_handler(uri: Uri) -> impl IntoResponse {
    tracing::error!("No route for {}", uri);
    (
        StatusCode::NOT_FOUND,
        Json(
            json!({ "message": format!("No route for {}", uri), "error_code": "ROUTE_NOT_FOUND" }),
        ),
    )
}

#[derive(Debug, Deserialize)]
struct VerifyParams {
    domain: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    domain: String,
    is_disposable: bool,
    source: String,
    checked_at: String,
}

async fn verify_handler(
    State(state): State<AppState>,
    Query(params): Query<VerifyParams>,
) -> impl IntoResponse {
    let domain_orig = params.domain.clone();
    let domain = params.domain.to_lowercase();
    let now = Utc::now().to_rfc3339();

    let is_disposable = state.domains.contains(&domain);

    (
        StatusCode::OK,
        Json(VerifyResponse {
            domain: domain_orig,
            is_disposable,
            source: "assets/blocklist.txt".into(),
            checked_at: now,
        }),
    )
}
