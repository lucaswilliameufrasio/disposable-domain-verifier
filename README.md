# Domain Verifier

# Installation

1. Clone the repository:

``` bash
git clone https://github.com/lucaswilliameufrasio/domain_verify_api.git
cd domain verifier
```

2. Build and run:

``` bash
cargo run --release
```

3. The server listens on port 9999 by default.

# Usage

Verify a domain:

```bash
curl 'http://localhost:9999/v1/domains/verify?domain=mailinator.com'
```

Sample response:

```json
{
  "domain": "mailinator.com",
  "is_disposable": true,
  "reason": "Listed as disposable",
  "source": "blocklist.txt",
  "checked_at": "2025-05-12T09:21:32.796957+00:00"
}
```