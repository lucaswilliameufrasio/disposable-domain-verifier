use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use arc_swap::ArcSwap;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::{StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    fs::File,
    io::{BufRead, BufReader, Write},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

type DomainSet = HashSet<String, ahash::RandomState>;

// --- Error Handling Standard ---

#[derive(Serialize)]
struct ApiError {
    message: String,
    error_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    extra: Option<Value>,
}

#[derive(Debug)]
enum AppError {
    Internal(String),
    BadRequest(String, String), // message, code
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, code, extra) = match self {
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg, "INTERNAL_SERVER_ERROR".to_string(), None),
            AppError::BadRequest(msg, code) => (StatusCode::BAD_REQUEST, msg, code, None),
        };

        let body = Json(ApiError {
            message,
            error_code: code,
            extra,
        });

        (status, body).into_response()
    }
}

// --- App Logic ---

/// Helper to read domains from a file path
fn load_domains_from_file(path: &str) -> Result<DomainSet, AppError> {
    let file = File::open(path).map_err(|e| AppError::Internal(format!("Failed to open blocklist: {}", e)))?;
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
        match e {
            AppError::Internal(msg) => tracing::error!("{}", msg),
            _ => tracing::error!("Error loading domains: {:?}", e),
        }
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

async fn fallback_handler(uri: Uri) -> AppError {
    tracing::error!("No route for {}", uri);
    AppError::BadRequest(format!("No route for {}", uri), "ROUTE_NOT_FOUND".into())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, Json(json!({ "status": "up" })))
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
    params: Result<Query<VerifyParams>, axum::extract::rejection::QueryRejection>,
) -> Result<impl IntoResponse, AppError> {
    let Query(params) = params.map_err(|e| {
        AppError::BadRequest(format!("Invalid query parameters: {}", e), "INVALID_QUERY_PARAMS".into())
    })?;

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

    Ok((
        StatusCode::OK,
        Json(VerifyResponse {
            domain,
            is_disposable,
            source: std::borrow::Cow::Borrowed("assets/blocklist.txt"),
            checked_at: now,
        }),
    ))
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
    fn test_load_domains_from_file() -> Result<(), AppError> {
        let mut file = NamedTempFile::new().map_err(|e| AppError::Internal(e.to_string()))?;
        writeln!(file, "example.com").unwrap();
        writeln!(file, "  SPAM.ORG  ").unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "disposable.net").unwrap();

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
        let params = Query(VerifyParams { domain: "DISPOSABLE.COM".to_string() });
        let response = verify_handler(State(state.clone()), Ok(params)).await.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Test with safe domain
        let params = Query(VerifyParams { domain: "google.com".to_string() });
        let response = verify_handler(State(state), Ok(params)).await.unwrap().into_response();
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
        assert_eq!(body["status"], "up");
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

        // Test with invalid query param (missing domain) - should return 400 with our standard error structure
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
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let err: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(err["error_code"], "INVALID_QUERY_PARAMS");
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST); // Fallback returns 400 for bad routes in our code
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error_code"], "ROUTE_NOT_FOUND");
    }

    #[tokio::test]
    async fn test_run_smoke() {
        std::fs::create_dir_all("assets").unwrap();
        if !std::path::Path::new("assets/blocklist.txt").exists() {
            std::fs::write("assets/blocklist.txt", "example.com").unwrap();
        }
        let result = run().await;
        assert!(result.is_ok());
    }
}
