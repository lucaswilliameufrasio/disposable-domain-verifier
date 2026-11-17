#!/usr/bin/env python3
"""Download and validate every source before atomically replacing the blocklist."""

import datetime
import hashlib
import os
from pathlib import Path
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
SOURCES = (
    ("community", "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf", 9000, 20000),
    ("fakefilter", "https://raw.githubusercontent.com/7c/fakefilter/main/txt/data.txt", 3500, 10000),
)
REQUIRED_PROTECTED = {"google.com", "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com"}
KNOWN = {"mailinator.com", "10minutemail.com", "guerrillamail.com"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(data, name):
    domains = set()
    for number, raw in enumerate(data.decode("utf-8").splitlines(), 1):
        domain = raw.strip().lower()
        if not domain or domain.startswith("#"):
            continue
        labels = domain.split(".")
        if (len(domain) > 253 or len(labels) < 2 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            or any(not (c.isascii() and (c.isalnum() or c == "-")) for c in label)
            for label in labels
        )):
            raise ValueError(f"Invalid domain in {name}:{number}: {domain}")
        domains.add(domain)
    return domains


def build(source_data, old_data, own_data, protected_data, excluded_data=b""):
    protected = parse(protected_data, "protected")
    if not REQUIRED_PROTECTED <= protected:
        raise ValueError("Required protected domains missing")
    old = parse(old_data, "current blocklist")
    own = parse(own_data, "local inclusions")
    excluded = parse(excluded_data, "local exclusions")
    if own & excluded:
        raise ValueError("Local inclusions conflict with exclusions")
    candidate = set(own)
    for name, url, minimum, maximum in SOURCES:
        data = source_data[name]
        if not 10000 <= len(data) <= 10485760:
            raise ValueError(f"Source {name} size outside limits")
        domains = parse(data, name)
        if not minimum <= len(domains) <= maximum:
            raise ValueError(f"Source {name} count outside limits: {len(domains)}")
        if not domains & KNOWN:
            raise ValueError(f"Source {name} lacks known domains")
        print(f"{name}: url={url} sha256={digest(data)} bytes={len(data)} domains={len(domains)} new_to_union={len(domains - candidate)}")
        candidate.update(domains)
    hits = candidate & protected
    if hits:
        raise ValueError(f"Protected legitimate domains found: {', '.join(sorted(hits))}")
    excluded_hits = candidate & excluded
    candidate.difference_update(excluded)
    if excluded_hits:
        print("Excluded locally reviewed domains: " + ", ".join(sorted(excluded_hits)))
    added, removed = candidate - old, old - candidate
    print(f"local={len(own)} old={len(old)} candidate={len(candidate)} added={len(added)} removed={len(removed)}")
    if len(added) > max(1000, len(old) // 10) or len(removed) > max(1000, len(old) // 10):
        raise ValueError("Abnormal change; refusing publication (manual investigation required)")
    return "".join(domain + "\n" for domain in sorted(candidate)).encode()


def main():
    print("UTC:", datetime.datetime.now(datetime.timezone.utc).isoformat())
    source_data = {}
    for name, url, _, _ in SOURCES:
        with urllib.request.urlopen(url, timeout=120) as response:
            source_data[name] = response.read(10485761)
    target = ROOT / "assets/blocklist.txt"
    result = build(source_data, target.read_bytes(),
                   (ROOT / "assets/confirmed-disposable-domains.txt").read_bytes(),
                   (ROOT / "assets/legitimate-domains.txt").read_bytes(),
                   (ROOT / "assets/blocklist-exclusions.txt").read_bytes())
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as tmp:
        temp_path = Path(tmp.name)
        try:
            tmp.write(result)
            tmp.flush()
            os.fchmod(tmp.fileno(), 0o644)
            os.fsync(tmp.fileno())
            os.replace(temp_path, target)
        finally:
            temp_path.unlink(missing_ok=True)
    print(f"Updated {target}; sha256={digest(result)}")


if __name__ == "__main__":
    main()
