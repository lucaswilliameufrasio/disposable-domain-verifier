use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use arc_swap::ArcSwap;
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
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

type DomainSet = HashSet<String, ahash::RandomState>;

/// Helper to read domains from a file path
fn load_domains_from_file(path: &str) -> std::io::Result<DomainSet> {
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
    domains: Arc<ArcSwap<DomainSet>>,
}

fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/v1/domains/verify", get(verify_handler))
        .route("/health-check", get(health_check))
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
        .fallback(fallback_handler)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber (logging)
    let _ = tracing_subscriber::fmt::try_init();

    // Resolve path: <current_dir>/assets/blocklist.txt
    let cwd = std::env::current_dir()?;
    let path_buffer = cwd.join("assets").join("blocklist.txt");
    let path = path_buffer.to_str().expect("Path not defined properly").to_string();

    // Initialize with local file first for immediate availability
    let initial_domains = load_domains_from_file(&path).unwrap_or_else(|e| {
        tracing::error!("Failed to load initial domains from {}: {}", path, e);
        HashSet::default()
    });
    
    let state = AppState {
        domains: Arc::new(ArcSwap::from_pointee(initial_domains)),
    };

    let port = std::env::var("PORT").unwrap_or("9999".to_string());

    // Build application
    let app = create_app(state);

    // Run server on localhost:<port>
    let address = SocketAddr::from((IpAddr::from(Ipv6Addr::UNSPECIFIED), port.parse()?));
    
    // In test environment, we might not want to actually bind
    #[cfg(not(test))]
    {
        let listener = tokio::net::TcpListener::bind(address).await?;
        tracing::info!("Starting server on {}", address);
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }

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

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "message": "ok" })))
}

#[derive(Debug, Deserialize)]
struct VerifyParams {
    domain: String,
}

#[derive(Serialize, Deserialize)]
struct VerifyResponse {
    domain: String,
    is_disposable: bool,
    source: std::borrow::Cow<'static, str>,
    checked_at: String,
}

async fn verify_handler(
    State(state): State<AppState>,
    Query(params): Query<VerifyParams>,
) -> impl IntoResponse {
    let domain = params.domain;
    
    // Fast-path: Check if already lowercase to avoid allocation
    let mut is_lowercase = true;
    for b in domain.bytes() {
        if b.is_ascii_uppercase() {
            is_lowercase = false;
            break;
        }
    }

    let search_domain = if is_lowercase {
        std::borrow::Cow::Borrowed(domain.as_str())
    } else {
        std::borrow::Cow::Owned(domain.to_ascii_lowercase())
    };

    // Use ArcSwap load to get a handle to the current set
    let domains = state.domains.load();
    let is_disposable = domains.contains(search_domain.as_ref());

    let now = Utc::now().to_rfc3339();

    (
        StatusCode::OK,
        Json(VerifyResponse {
            domain,
            is_disposable,
            source: std::borrow::Cow::Borrowed("assets/blocklist.txt"),
            checked_at: now,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    #[test]
    fn test_load_domains_from_file() -> std::io::Result<()> {
        let mut file = NamedTempFile::new()?;
        writeln!(file, "example.com")?;
        writeln!(file, "  SPAM.ORG  ")?;
        writeln!(file, "# comment")?;
        writeln!(file, "")?;
        writeln!(file, "disposable.net")?;

        let domains = load_domains_from_file(file.path().to_str().unwrap())?;
        
        assert_eq!(domains.len(), 3);
        assert!(domains.contains("example.com"));
        assert!(domains.contains("spam.org"));
        assert!(domains.contains("disposable.net"));
        assert!(!domains.contains("# comment"));
        
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_handler_logic() {
        let mut domains = DomainSet::default();
        domains.insert("disposable.com".to_string());
        
        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(domains)),
        };

        // Test with disposable domain
        let params = VerifyParams { domain: "DISPOSABLE.COM".to_string() };
        let response = verify_handler(State(state.clone()), Query(params)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Test with safe domain
        let params = VerifyParams { domain: "google.com".to_string() };
        let response = verify_handler(State(state), Query(params)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_integration() {
        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(DomainSet::default())),
        };
        let app = create_app(state);

        let response = app
            .oneshot(Request::builder().uri("/health-check").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["message"], "ok");
    }

    #[tokio::test]
    async fn test_verify_integration() {
        let mut domains = DomainSet::default();
        domains.insert("trashmail.com".to_string());
        
        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(domains)),
        };
        let app = create_app(state);

        // Test disposable domain
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/domains/verify?domain=trashmail.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(resp.is_disposable);
        assert_eq!(resp.domain, "trashmail.com");

        // Test safe domain
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/domains/verify?domain=google.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let resp: VerifyResponse = serde_json::from_slice(&body).unwrap();
        assert!(!resp.is_disposable);

        // Test with X-Forwarded-For header (for coverage of tracing layer)
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/domains/verify?domain=google.com")
                    .header("x-forwarded-for", "1.2.3.4")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test with invalid query param (missing domain) - should return 400
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/domains/verify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_fallback_handler() {
        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(DomainSet::default())),
        };
        let app = create_app(state);

        let response = app
            .oneshot(Request::builder().uri("/not-found").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "ROUTE_NOT_FOUND");
    }

    #[test]
    fn test_load_domains_file_not_found() {
        let result = load_domains_from_file("non_existent_file.txt");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_run_smoke() {
        // Ensure assets/blocklist.txt exists for the test
        std::fs::create_dir_all("assets").unwrap();
        if !std::path::Path::new("assets/blocklist.txt").exists() {
            std::fs::write("assets/blocklist.txt", "example.com").unwrap();
        }

        // Now run() will only execute initialization logic in test mode
        let result = run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tracing_connect_info() {
        use axum::extract::connect_info::MockConnectInfo;

        let state = AppState {
            domains: Arc::new(ArcSwap::from_pointee(DomainSet::default())),
        };
        let app = create_app(state);

        let addr = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        
        let response = app
            .layer(MockConnectInfo(addr))
            .oneshot(
                Request::builder()
                    .uri("/health-check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
