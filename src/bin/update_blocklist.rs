use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

const MAX_BYTES: usize = 10_485_760;
const PROTECTED: [&str; 6] = [
    "google.com",
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
];
const KNOWN: [&str; 3] = ["mailinator.com", "10minutemail.com", "guerrillamail.com"];

struct Source<'a> {
    name: &'static str,
    url: &'a str,
    min: usize,
    max: usize,
}

const SOURCES: [Source<'static>; 2] = [
    Source {
        name: "community",
        url: "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
        min: 9000,
        max: 20000,
    },
    Source {
        name: "fakefilter",
        url: "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt",
        min: 3500,
        max: 10000,
    },
];

fn parse(data: &[u8], name: &str) -> Result<BTreeSet<String>, String> {
    let text = std::str::from_utf8(data).map_err(|e| format!("Invalid UTF-8 in {name}: {e}"))?;
    let mut domains = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let domain = raw.trim().to_lowercase();
        if domain.is_empty() || domain.starts_with('#') {
            continue;
        }
        let labels: Vec<_> = domain.split('.').collect();
        if domain.len() > 253
            || labels.len() < 2
            || labels.iter().any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(format!("Invalid domain in {name}:{}: {domain}", index + 1));
        }
        domains.insert(domain);
    }
    Ok(domains)
}

fn digest(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn build(
    sources: &[(&Source<'_>, &[u8])],
    old: &[u8],
    own: &[u8],
    protected: &[u8],
    excluded: &[u8],
) -> Result<Vec<u8>, String> {
    let protected = parse(protected, "protected")?;
    if PROTECTED.iter().any(|domain| !protected.contains(*domain)) {
        return Err("Required protected domains missing".into());
    }
    let old = parse(old, "current blocklist")?;
    let own = parse(own, "local inclusions")?;
    let excluded = parse(excluded, "local exclusions")?;
    if !own.is_disjoint(&excluded) {
        return Err("Local inclusions conflict with exclusions".into());
    }
    let mut candidate = own.clone();
    for (source, data) in sources {
        if !(10_000..=MAX_BYTES).contains(&data.len()) {
            return Err(format!("Source {} size outside limits", source.name));
        }
        let domains = parse(data, source.name)?;
        if !(source.min..=source.max).contains(&domains.len()) {
            return Err(format!(
                "Source {} count outside limits: {}",
                source.name,
                domains.len()
            ));
        }
        if !KNOWN.iter().any(|domain| domains.contains(*domain)) {
            return Err(format!("Source {} lacks known domains", source.name));
        }
        println!(
            "{}: url={} sha256={} bytes={} domains={} new_to_union={}",
            source.name,
            source.url,
            digest(data),
            data.len(),
            domains.len(),
            domains.difference(&candidate).count()
        );
        candidate.extend(domains);
    }
    let hits: Vec<_> = candidate.intersection(&protected).cloned().collect();
    if !hits.is_empty() {
        return Err(format!(
            "Protected legitimate domains found: {}",
            hits.join(", ")
        ));
    }
    let excluded_hits: Vec<_> = candidate.intersection(&excluded).cloned().collect();
    for domain in &excluded {
        candidate.remove(domain);
    }
    if !excluded_hits.is_empty() {
        println!(
            "Excluded locally reviewed domains: {}",
            excluded_hits.join(", ")
        );
    }
    let added = candidate.difference(&old).count();
    let removed = old.difference(&candidate).count();
    println!(
        "local={} old={} candidate={} added={} removed={}",
        own.len(),
        old.len(),
        candidate.len(),
        added,
        removed
    );
    if added > 1000.max(old.len() / 10) || removed > 1000.max(old.len() / 10) {
        return Err("Abnormal change; refusing publication (manual investigation required)".into());
    }
    let mut result = candidate
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n")
        .into_bytes();
    if !result.is_empty() {
        result.push(b'\n');
    }
    Ok(result)
}

async fn download(
    client: &reqwest::Client,
    source: &Source<'_>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut response = client.get(source.url).send().await?.error_for_status()?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_BYTES {
            return Err(format!("Source {} size outside limits", source.name).into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn publish(target: &Path, data: &[u8]) -> Result<(), Box<dyn Error>> {
    let parent = target.parent().ok_or("Blocklist target has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(data)?;
    temporary.flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))?;
    }
    temporary.as_file().sync_all()?;
    temporary.persist(target)?;
    Ok(())
}

async fn update(
    client: &reqwest::Client,
    root: &Path,
    sources: &[Source<'_>; 2],
) -> Result<(), Box<dyn Error>> {
    let (first, second) =
        tokio::try_join!(download(client, &sources[0]), download(client, &sources[1]))?;
    let root = root.join("assets");
    let target = root.join("blocklist.txt");
    let result = build(
        &[(&sources[0], &first), (&sources[1], &second)],
        &fs::read(&target)?,
        &fs::read(root.join("confirmed-disposable-domains.txt"))?,
        &fs::read(root.join("legitimate-domains.txt"))?,
        &fs::read(root.join("blocklist-exclusions.txt"))?,
    )?;
    publish(&target, &result)?;
    println!("Updated {}; sha256={}", target.display(), digest(&result));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = match args.next() {
        None => std::env::current_dir()?,
        Some(flag) if flag == "--root" => args.next().ok_or("--root requires a directory")?.into(),
        Some(_) => return Err("Usage: update-blocklist [--root DIRECTORY]".into()),
    };
    if args.next().is_some() {
        return Err("Usage: update-blocklist [--root DIRECTORY]".into());
    }
    println!("UTC: {}", chrono::Utc::now().to_rfc3339());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;
    update(&client, &root, &SOURCES).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protected() -> Vec<u8> {
        format!("{}\n", PROTECTED.join("\n")).into_bytes()
    }

    fn source() -> Source<'static> {
        Source {
            name: "test",
            url: "https://example.test/",
            min: 1,
            max: 2000,
        }
    }

    fn payload(domains: &str) -> Vec<u8> {
        format!("{domains}\n#{}", "x".repeat(10_000)).into_bytes()
    }

    #[test]
    fn merges_normalizes_deduplicates_and_excludes() {
        let data = payload("Mailinator.COM\nshared.example\nshared.example\nother.example");
        let output = build(
            &[(&source(), &data)],
            b"mailinator.com\n",
            b"local.example\n",
            &protected(),
            b"other.example\n",
        )
        .unwrap();
        assert_eq!(output, b"local.example\nmailinator.com\nshared.example\n");
    }

    #[test]
    fn fails_closed_for_invalid_data_and_protected_conflicts() {
        let data = payload("mailinator.com");
        assert!(
            build(
                &[(&source(), &data)],
                b"mailinator.com\n",
                b"invalid domain\n",
                &protected(),
                b""
            )
            .is_err()
        );
        assert!(
            build(
                &[(&source(), &data)],
                b"mailinator.com\n",
                b"gmail.com\n",
                &protected(),
                b"gmail.com\n"
            )
            .is_err()
        );
        assert!(
            build(
                &[(&source(), &data)],
                b"mailinator.com\n",
                b"gmail.com\n",
                &protected(),
                b""
            )
            .is_err()
        );
        assert!(
            build(
                &[(&source(), &data)],
                b"mailinator.com\n",
                b"",
                b"gmail.com\n",
                b""
            )
            .is_err()
        );
        assert!(parse(&[0xff], "invalid").is_err());
    }

    #[test]
    fn rejects_missing_known_domains_bad_sizes_and_large_deltas() {
        assert!(
            build(
                &[(&source(), b"mailinator.com")],
                b"",
                b"",
                &protected(),
                b""
            )
            .is_err()
        );
        let data = payload("not-known.example");
        assert!(build(&[(&source(), &data)], b"", b"", &protected(), b"").is_err());
        let data = payload(&format!(
            "mailinator.com\n{}",
            (0..1100)
                .map(|i| format!("d{i}.example"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
        assert!(
            build(
                &[(&source(), &data)],
                b"mailinator.com\n",
                b"",
                &protected(),
                b""
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn update_publishes_only_after_both_http_sources_pass() {
        use axum::{Router, http::StatusCode, routing::get};
        let app = Router::new()
            .route(
                "/one",
                get(|| async { payload("Mailinator.com\nshared.example") }),
            )
            .route(
                "/two",
                get(|| async { payload("mailinator.com\nother.example") }),
            )
            .route(
                "/unavailable",
                get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            )
            .route(
                "/protected",
                get(|| async { payload("mailinator.com\ngmail.com") }),
            )
            .route("/oversized", get(|| async { vec![b'x'; MAX_BYTES + 1] }))
            .route(
                "/truncated-list",
                get(|| async { b"mailinator.com\n".to_vec() }),
            )
            .route("/stalled", get(std::future::pending::<StatusCode>));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let assets = temp.path().join("assets");
        fs::create_dir(&assets).unwrap();
        fs::write(
            assets.join("confirmed-disposable-domains.txt"),
            b"local.example\n",
        )
        .unwrap();
        fs::write(
            assets.join("blocklist-exclusions.txt"),
            b"other.example\ngmail.com\n",
        )
        .unwrap();
        fs::write(assets.join("legitimate-domains.txt"), protected()).unwrap();
        let target = assets.join("blocklist.txt");
        let original = b"mailinator.com\n";
        fs::write(&target, original).unwrap();

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let first = format!("{base}/one");
        for (path, expected) in [
            ("unavailable", "503"),
            ("protected", "Protected legitimate"),
            ("oversized", "size outside limits"),
            ("truncated-list", "size outside limits"),
        ] {
            let second = format!("{base}/{path}");
            let inputs = [
                Source {
                    url: &first,
                    ..source()
                },
                Source {
                    url: &second,
                    ..source()
                },
            ];
            let error = update(&client, temp.path(), &inputs).await.unwrap_err();
            assert!(error.to_string().contains(expected), "{path}: {error}");
            assert_eq!(fs::read(&target).unwrap(), original, "{path}");
            assert_eq!(fs::read_dir(&assets).unwrap().count(), 4, "{path}");
        }

        let stalled = format!("{base}/stalled");
        let timeout_client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        let stalled_inputs = [
            Source {
                url: &first,
                ..source()
            },
            Source {
                url: &stalled,
                ..source()
            },
        ];
        let error = update(&timeout_client, temp.path(), &stalled_inputs)
            .await
            .unwrap_err();
        assert!(
            error
                .downcast_ref::<reqwest::Error>()
                .is_some_and(reqwest::Error::is_timeout)
        );
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(fs::read_dir(&assets).unwrap().count(), 4);

        let second = format!("{base}/two");
        let inputs = [
            Source {
                url: &first,
                ..source()
            },
            Source {
                url: &second,
                ..source()
            },
        ];
        update(&client, temp.path(), &inputs).await.unwrap();
        assert_eq!(
            fs::read(&target).unwrap(),
            b"local.example\nmailinator.com\nshared.example\n"
        );
        assert_eq!(fs::read_dir(&assets).unwrap().count(), 4);
        server.abort();
    }

    #[test]
    #[ignore = "manual benchmark"]
    fn benchmark_parse_existing_blocklist() {
        let data = include_bytes!("../../assets/blocklist.txt");
        let mut samples = Vec::new();
        parse(data, "warmup").unwrap();
        for _ in 0..20 {
            let start = std::time::Instant::now();
            parse(data, "benchmark").unwrap();
            samples.push(start.elapsed());
        }
        samples.sort();
        println!(
            "bytes={} median_ms={:.3}",
            data.len(),
            samples[10].as_secs_f64() * 1000.0
        );
    }

    #[test]
    #[ignore = "requires independently prepared source fixtures"]
    fn matches_python_candidate_from_identical_sources() {
        let fixture = std::env::var_os("BLOCKLIST_PARITY_FIXTURE").expect("fixture directory");
        let fixture = Path::new(&fixture);
        let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets");
        let first = fs::read(fixture.join("community")).unwrap();
        let second = fs::read(fixture.join("fakefilter")).unwrap();
        let expected = fs::read(fixture.join("expected")).unwrap();
        let old = fs::read(assets.join("blocklist.txt")).unwrap();
        let own = fs::read(assets.join("confirmed-disposable-domains.txt")).unwrap();
        let protected = fs::read(assets.join("legitimate-domains.txt")).unwrap();
        let excluded = fs::read(assets.join("blocklist-exclusions.txt")).unwrap();
        let result = build(
            &[(&SOURCES[0], &first), (&SOURCES[1], &second)],
            &old,
            &own,
            &protected,
            &excluded,
        )
        .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn publishes_atomically_to_target_directory() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("blocklist.txt");
        fs::write(&target, "old\n").unwrap();
        publish(&target, b"new\n").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new\n");
    }
}
