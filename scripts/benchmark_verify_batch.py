"""Compare HTTP request counts, bytes and latency for 100 lookups locally."""

import argparse
import json
import math
import os
from pathlib import Path
import socket
import statistics
import subprocess
import time
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "/v1/domains/verify"
DOMAIN_COUNT = 100
EXPECTED = [i % 2 == 0 for i in range(DOMAIN_COUNT)]
ROUNDS = 8
SAMPLES_PER_ROUND = 50


def request(method, path, payload=b""):
    headers = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n"
    if payload:
        headers += f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
    return (headers + "\r\n").encode("ascii") + payload


def read_response(reader):
    line = reader.readline()
    if not line.startswith(b"HTTP/1.1 200 "):
        raise RuntimeError(f"unexpected status: {line!r}")
    size = len(line)
    length = None
    while True:
        line = reader.readline()
        size += len(line)
        if line == b"\r\n":
            break
        if not line:
            raise RuntimeError("incomplete response headers")
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    if length is None:
        raise RuntimeError("missing Content-Length")
    body = reader.read(length)
    if len(body) != length:
        raise RuntimeError("incomplete response body")
    return body, size + length


def verify_results(scenario, bodies):
    if scenario == "single-json":
        actual = [json.loads(body)["is_disposable"] for body in bodies]
    elif scenario == "single-compact":
        actual = [body[0] == ord("1") for body in bodies if body in (b"0", b"1")]
    elif scenario == "batch-json":
        actual = json.loads(bodies[0])["results"]
    else:
        packed = bodies[0]
        if len(packed) != math.ceil(DOMAIN_COUNT / 8):
            raise RuntimeError("unexpected bitset length")
        actual = [bool(packed[i // 8] & (1 << (i % 8))) for i in range(DOMAIN_COUNT)]
    if actual != EXPECTED:
        raise RuntimeError(f"incorrect results: {scenario}")


def sample(host, port, scenario, requests, count):
    elapsed, transferred = [], []
    with socket.create_connection((host, port), timeout=5) as conn, conn.makefile("rb") as reader:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for _ in range(count):
            bodies = []
            size = 0
            start = time.perf_counter_ns()
            for frame in requests:
                conn.sendall(frame)
                body, response_bytes = read_response(reader)
                bodies.append(body)
                size += len(frame) + response_bytes
            verify_results(scenario, bodies)
            elapsed.append((time.perf_counter_ns() - start) / 1e6)
            transferred.append(size)
    return statistics.mean(transferred), statistics.median(elapsed), sorted(elapsed)[math.ceil(.95 * count) - 1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", choices=("::1", "127.0.0.1"), default="::1", help="loopback address (default: ::1)")
    host = parser.parse_args().host
    blocklist = set((ROOT / "assets/blocklist.txt").read_text().splitlines())
    listed = iter(sorted(blocklist)[: DOMAIN_COUNT // 2])
    domains = [
        next(listed) if expected else f"fixture-{index}.example"
        for index, expected in enumerate(EXPECTED)
    ]
    payload = json.dumps({"domains": domains}, separators=(",", ":")).encode("ascii")
    scenarios = {
        "single-json": [request("GET", f"{PREFIX}?{urlencode({'domain': d})}") for d in domains],
        "single-compact": [request("GET", f"{PREFIX}/compact?{urlencode({'domain': d})}") for d in domains],
        "batch-json": [request("POST", f"{PREFIX}/batch", payload)],
        "batch-bits": [request("POST", f"{PREFIX}/batch/compact", payload)],
    }
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET
    with socket.socket(family) as reservation:
        reservation.bind((host, 0))
        port = reservation.getsockname()[1]
    with subprocess.Popen(
        [ROOT / "target/release/disposable-domain-verifier"],
        cwd=ROOT, env=dict(os.environ, PORT=str(port), RUST_LOG="off"), stdout=subprocess.DEVNULL,
    ) as app:
        try:
            for _ in range(100):
                if app.poll() is not None:
                    raise RuntimeError("server exited before startup")
                try:
                    with socket.create_connection((host, port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.02)
            else:
                raise RuntimeError("local server did not start")

            results = {key: [] for key in scenarios}
            for key, requests in scenarios.items():
                sample(host, port, key, requests, 20)
            order = list(scenarios)
            for index in range(ROUNDS):
                offset = index % len(order)
                for key in order[offset:] + order[:offset]:
                    results[key].append(sample(host, port, key, scenarios[key], SAMPLES_PER_ROUND))
            print(f"HTTP/1.1 loopback ({host}), keep-alive, {ROUNDS} rounds × {SAMPLES_PER_ROUND} samples/format")
            print("format          requests  HTTP bytes   p50 ms   p95 ms  (per 100 lookups)")
            for key, rows in results.items():
                size, p50, p95 = (statistics.median(column) for column in zip(*rows))
                print(f"{key:15} {len(scenarios[key]):8}  {size:10.1f}  {p50:7.3f}  {p95:7.3f}")
        finally:
            if app.poll() is None:
                app.terminate()


if __name__ == "__main__":
    main()
