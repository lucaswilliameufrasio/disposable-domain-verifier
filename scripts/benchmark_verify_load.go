// Measure closed-loop latency and throughput of 100-domain batches over loopback.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

type sample struct {
	latencies []time.Duration
	errors    int
	firstErr  error
}

func measure(client *http.Client, endpoint, format string, payload, packed []byte, want []bool, workers int, duration time.Duration) (sample, time.Duration) {
	results := make([]sample, workers)
	transport := make(chan struct{})
	var deadline time.Time
	var group sync.WaitGroup
	for id := range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-transport
			out := &results[id]
			for time.Now().Before(deadline) {
				start := time.Now()
				err := check(client, endpoint, format, payload, packed, want)
				if err != nil {
					out.errors++
					if out.firstErr == nil {
						out.firstErr = err
					}
				} else {
					out.latencies = append(out.latencies, time.Since(start))
				}
			}
		}()
	}
	start := time.Now()
	deadline = start.Add(duration)
	close(transport)
	group.Wait()
	elapsed := time.Since(start)
	var combined sample
	for _, result := range results {
		combined.latencies = append(combined.latencies, result.latencies...)
		combined.errors += result.errors
		if combined.firstErr == nil {
			combined.firstErr = result.firstErr
		}
	}
	slices.Sort(combined.latencies)
	return combined, elapsed
}

func check(client *http.Client, endpoint, format string, payload, packed []byte, want []bool) error {
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	switch format {
	case "bits":
		if resp.Header.Get("Content-Type") != "application/octet-stream" || !bytes.Equal(body, packed) {
			return fmt.Errorf("incorrect binary response")
		}
	case "json":
		var verdict struct{ Results []bool }
		if resp.Header.Get("Content-Type") != "application/json" ||
			json.Unmarshal(body, &verdict) != nil || !slices.Equal(verdict.Results, want) {
			return fmt.Errorf("incorrect JSON response")
		}
	}
	return nil
}

func run() error {
	port := flag.Int("port", 9999, "local verifier port")
	duration := flag.Duration("duration", 2*time.Second, "time per measurement (1–10s)")
	rounds := flag.Int("rounds", 3, "number of rounds (1–5)")
	flag.Parse()
	if *port < 1 || *port > 65535 || *rounds < 1 || *rounds > 5 || *duration < time.Second || *duration > 10*time.Second {
		return fmt.Errorf("port or benchmark bounds invalid")
	}

	data, err := os.ReadFile("assets/blocklist.txt")
	if err != nil {
		return err
	}
	listed := strings.Fields(string(data))
	if len(listed) < 50 {
		return fmt.Errorf("blocklist needs at least 50 entries")
	}
	domains, want, packed := make([]string, 100), make([]bool, 100), make([]byte, 13)
	for i := range domains {
		if i%2 == 0 {
			domains[i] = listed[i/2]
			if i%4 == 0 {
				domains[i] = strings.ToUpper(domains[i])
			}
			want[i] = true
			packed[i/8] |= 1 << (i % 8)
		} else {
			domains[i] = fmt.Sprintf("fixture-%d.example", i)
		}
	}
	payload, err := json.Marshal(map[string][]string{"domains": domains})
	if err != nil {
		return err
	}
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", *port)}
	fmt.Printf("Go %s, GOMAXPROCS=%d, %d rounds, duration=%s, JSON request body=%d bytes\n",
		runtime.Version(), runtime.GOMAXPROCS(0), *rounds, *duration, len(payload))
	fmt.Println("round,transport,response,connections,ok,errors,batches_per_second,p50_us,p95_us,p99_us")
	type variant struct{ scheme, format string }
	matrix := []variant{{"http", "json"}, {"https", "json"}, {"http", "bits"}, {"https", "bits"}}
	for round := range *rounds {
		for _, workers := range []int{1, 8, 32} {
			for offset := range matrix {
				mode := matrix[(offset+round)%len(matrix)]
				if err := scenario(target, mode.scheme, mode.format, workers, *duration, round+1, payload, packed, want); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func scenario(target *url.URL, scheme, format string, workers int, duration time.Duration, round int, payload, packed []byte, want []bool) error {
	upstream := &http.Transport{MaxIdleConns: workers, MaxIdleConnsPerHost: workers, MaxConnsPerHost: workers}
	defer upstream.CloseIdleConnections()
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = upstream
	server := httptest.NewUnstartedServer(proxy)
	if scheme == "https" {
		server.StartTLS() // Default HTTP/1.1; client trusts only the test server cert.
	} else {
		server.Start()
	}
	defer server.Close()
	client := server.Client()
	client.Timeout = 2 * time.Second
	transport := client.Transport.(*http.Transport)
	transport.MaxIdleConns = workers
	transport.MaxIdleConnsPerHost = workers
	transport.MaxConnsPerHost = workers
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer transport.CloseIdleConnections()
	endpoint := server.URL + "/v1/domains/verify/batch"
	if format == "bits" {
		endpoint += "/compact"
	}
	healthCtx, cancelHealth := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelHealth()
	req, err := http.NewRequestWithContext(healthCtx, "GET", target.String()+"/health-check", nil)
	if err != nil {
		return err
	}
	resp, err := upstream.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("local verifier health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local verifier health check returned %d", resp.StatusCode)
	}
	warm, _ := measure(client, endpoint, format, payload, packed, want, workers, 300*time.Millisecond)
	if warm.errors > 0 {
		return fmt.Errorf("warmup: %d errors, first: %w", warm.errors, warm.firstErr)
	}
	result, elapsed := measure(client, endpoint, format, payload, packed, want, workers, duration)
	n := len(result.latencies)
	if n == 0 {
		return fmt.Errorf("no successful batches: %v", result.firstErr)
	}
	percentile := func(p float64) float64 {
		return float64(result.latencies[int(math.Ceil(p*float64(n)))-1]) / float64(time.Microsecond)
	}
	fmt.Printf("%d,%s,%s,%d,%d,%d,%.0f,%.1f,%.1f,%.1f\n", round, scheme, format, workers,
		n, result.errors, float64(n)/elapsed.Seconds(), percentile(.50), percentile(.95), percentile(.99))
	if result.errors > 0 {
		return fmt.Errorf("measurement: %d errors, first: %w", result.errors, result.firstErr)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
