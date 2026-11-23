#[path = "../src/main.rs"]
#[allow(dead_code, unused_imports)]
mod service;

use axum::{body::Body, http::Request};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use http_body_util::BodyExt;
use std::collections::HashSet;
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;
use tower::ServiceExt;

fn previous_two_pass_normalization(domain: &str) -> Option<std::borrow::Cow<'_, str>> {
    if domain.len() > 253
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return None;
    }
    if !domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return None;
    }
    if domain.bytes().all(|byte| !byte.is_ascii_uppercase()) {
        Some(std::borrow::Cow::Borrowed(domain))
    } else {
        Some(std::borrow::Cow::Owned(domain.to_ascii_lowercase()))
    }
}

fn lookup_benchmark(c: &mut Criterion) {
    let mut normalization = c.benchmark_group("hostname_normalization");
    for domain in ["example.com", "Mail.Example.COM"] {
        normalization.bench_function(format!("one_pass/{domain}"), |b| {
            b.iter(|| service::normalize_valid_domain(black_box(domain)))
        });
        normalization.bench_function(format!("previous_two_pass/{domain}"), |b| {
            b.iter(|| previous_two_pass_normalization(black_box(domain)))
        });
    }
    normalization.finish();

    let mut group = c.benchmark_group("verify_http_request");
    for size in [10_000, 100_000, 1_000_000] {
        let domains = (0..size).map(|i| format!("disposable-{i}.example"));
        let app = service::benchmark_app_with_domains(domains);
        let hit = format!("disposable-{}.example", size - 1);
        let miss = "legitimate.example";
        for (case, domain) in [("hit", hit.as_str()), ("miss", miss)] {
            group.bench_with_input(BenchmarkId::new(case, size), &app, |b, app| {
                let runtime = Runtime::new().expect("Tokio runtime");
                b.to_async(&runtime).iter(|| async {
                    let request = Request::builder()
                        .uri(format!("/v1/domains/verify?domain={}", black_box(domain)))
                        .body(Body::empty())
                        .unwrap();
                    let response = app.clone().oneshot(request).await.unwrap();
                    black_box(response.into_body().collect().await.unwrap());
                });
            });
        }
    }
    group.finish();
}

fn concurrent_load_benchmark(c: &mut Criterion) {
    let app =
        service::benchmark_app_with_domains((0..10_000).map(|i| format!("disposable-{i}.example")));
    let runtime = Runtime::new().expect("Tokio runtime");
    let mut group = c.benchmark_group("http_concurrent_load");
    group.measurement_time(Duration::from_secs(5));
    for concurrency in [1, 16, 64] {
        group.throughput(criterion::Throughput::Elements(concurrency as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &concurrency,
            |b, &n| {
                b.to_async(&runtime).iter(|| async {
                    let mut requests = Vec::with_capacity(n);
                    for index in 0..n {
                        let app = app.clone();
                        requests.push(tokio::spawn(async move {
                            let request = Request::builder()
                                .uri(format!(
                                    "/v1/domains/verify?domain=disposable-{index}.example"
                                ))
                                .body(Body::empty())
                                .unwrap();
                            app.oneshot(request).await.unwrap()
                        }));
                    }
                    for request in requests {
                        black_box(request.await.unwrap());
                    }
                });
            },
        );
    }
    group.finish();
}

// Candidate wire format for comparison only: one length byte per ASCII hostname.
// This only frames the body; hostname validation remains a separate step.
fn decode_binary_domains(mut body: &[u8]) -> Option<Vec<&str>> {
    let mut domains = Vec::with_capacity(100);
    while let Some((&len, rest)) = body.split_first() {
        if len == 0 || len > 253 || domains.len() == 100 {
            return None;
        }
        let (domain, remaining) = rest.split_at_checked(usize::from(len))?;
        domains.push(std::str::from_utf8(domain).ok()?);
        body = remaining;
    }
    if domains.is_empty() {
        return None;
    }
    Some(domains)
}

fn batch_stages_benchmark(c: &mut Criterion) {
    let set: HashSet<_, ahash::RandomState> = (0..13_500)
        .map(|i| format!("disposable-{i}.example"))
        .collect();
    let inputs: Vec<_> = (0..100)
        .map(|i| match i % 4 {
            0 => format!("Disposable-{i}.Example"),
            2 => format!("disposable-{i}.example"),
            _ => format!("legitimate-{i}.example"),
        })
        .collect();
    let normalized: Vec<_> = inputs
        .iter()
        .map(|domain| service::normalize_valid_domain(domain).unwrap())
        .collect();
    let json = serde_json::to_vec(&serde_json::json!({ "domains": inputs })).unwrap();
    let mut binary = Vec::new();
    for domain in &inputs {
        binary.push(u8::try_from(domain.len()).unwrap());
        binary.extend_from_slice(domain.as_bytes());
    }
    assert_eq!(decode_binary_domains(&binary).unwrap(), inputs);

    let mut group = c.benchmark_group("batch_stages_100");
    group.bench_function("parse_json", |b| {
        b.iter(|| serde_json::from_slice::<service::BatchVerifyRequest>(black_box(&json)).unwrap())
    });
    group.bench_function("parse_binary_experiment", |b| {
        b.iter(|| decode_binary_domains(black_box(&binary)).unwrap())
    });
    group.bench_function("normalize", |b| {
        b.iter(|| {
            for domain in black_box(&inputs) {
                black_box(service::normalize_valid_domain(domain));
            }
        })
    });
    group.bench_function("lookup_normalized", |b| {
        b.iter(|| {
            for domain in black_box(&normalized) {
                black_box(set.contains(domain.as_ref()));
            }
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    lookup_benchmark,
    concurrent_load_benchmark,
    batch_stages_benchmark
);
criterion_main!(benches);
