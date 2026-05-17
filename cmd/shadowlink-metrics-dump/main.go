package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:9090/metrics", "metrics endpoint")
	auth := flag.String("auth", "", "Bearer token (optional)")
	flag.Parse()

	req, _ := http.NewRequest("GET", *url, nil)
	if *auth != "" {
		req.Header.Set("Authorization", "Bearer "+*auth)
	}
	cli := &http.Client{Timeout: 5 * time.Second}
	resp, err := cli.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetch:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	prettyDump(string(body))
}

func prettyDump(body string) {
	lines := strings.Split(body, "\n")
	groups := map[string][]string{}
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		group := classify(ln)
		groups[group] = append(groups[group], ln)
	}
	order := []string{"Cold-start", "Bypass routing", "Rate-limit", "WS frame anomaly", "Other"}
	for _, g := range order {
		ls, ok := groups[g]
		if !ok {
			continue
		}
		fmt.Printf("=== %s ===\n", g)
		for _, ln := range ls {
			fmt.Println("  ", ln)
		}
		fmt.Println()
	}
}

func classify(ln string) string {
	switch {
	case strings.Contains(ln, "first_stream") || strings.Contains(ln, "pool_warmup") || strings.Contains(ln, "decoy_received"):
		return "Cold-start"
	case strings.Contains(ln, "bypass_"):
		return "Bypass routing"
	case strings.Contains(ln, "ratelimit_"):
		return "Rate-limit"
	case strings.Contains(ln, "ws_frame_anomaly") || strings.Contains(ln, "frame_anomaly"):
		return "WS frame anomaly"
	default:
		return "Other"
	}
}
