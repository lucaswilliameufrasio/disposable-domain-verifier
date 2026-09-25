#[path = "../src/main.rs"]
#[allow(dead_code, unused_imports)]
mod service;

use axum::{body::Body, http::Request};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use http_body_util::BodyExt;
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;
use tower::ServiceExt;

fn lookup_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("exact_domain_lookup");
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

criterion_group!(benches, lookup_benchmark, concurrent_load_benchmark);
criterion_main!(benches);
