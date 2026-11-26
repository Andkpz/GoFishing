package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	openPhishFeedURL = "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt"
	openPhishRefreshPeriod = 12 * time.Hour
	openPhishMaxBytes      = 8 << 20
	googleSafeBrowsingURL  = "https://safebrowsing.googleapis.com/v5alpha1/urls:search"
	threatIntelHTTPTimeout = 1800 * time.Millisecond
	threatIntelCacheMax    = 10000
)

type ThreatIntelReport struct {
	Status    string   `json:"status"` // hit, clean, partial, unavailable
	Providers []string `json:"providers,omitempty"`
	Threats   []string `json:"threats,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
}

type googleThreatResponse struct {
	Threats []struct {
		URL         string   `json:"url"`
		ThreatTypes []string `json:"threatTypes"`
	} `json:"threats"`
	CacheDuration string `json:"cacheDuration"`
}

type threatCacheEntry struct {
	report    ThreatIntelReport
	expiresAt time.Time
}

var (
	threatHTTPClient = &http.Client{Timeout: threatIntelHTTPTimeout}
	openPhishMu      sync.RWMutex
	openPhishURLs    = make(map[string]struct{})
	openPhishUpdated time.Time
	threatCacheMu    sync.Mutex
	threatCache      = make(map[string]threatCacheEntry)
)

// initThreatIntel запускает обновление OpenPhish в фоне. Google Safe Browsing
// включается отдельно через GOOGLE_SAFE_BROWSING_API_KEY.
func initThreatIntel() {
	go func() {
		refreshOpenPhishFeed()
		ticker := time.NewTicker(openPhishRefreshPeriod)
		defer ticker.Stop()
		for range ticker.C {
			refreshOpenPhishFeed()
		}
	}()
}

func refreshOpenPhishFeed() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, openPhishFeedURL, nil)
	if err != nil {
		log.Printf("OpenPhish: create request: %v", err)
		return
	}
	req.Header.Set("User-Agent", "PhishDetector/1.0")
	resp, err := threatHTTPClient.Do(req)
	if err != nil {
		log.Printf("OpenPhish: feed unavailable: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("OpenPhish: unexpected HTTP status: %s", resp.Status)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, openPhishMaxBytes+1))
	if err != nil {
		log.Printf("OpenPhish: read feed: %v", err)
		return
	}
	if len(data) > openPhishMaxBytes {
		log.Printf("OpenPhish: feed exceeds %d bytes", openPhishMaxBytes)
		return
	}

	updated := make(map[string]struct{}, 1024)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		canonical, err := canonicalThreatURL(line)
		if err == nil {
			updated[canonical] = struct{}{}
		}
	}
	if len(updated) == 0 {
		log.Printf("OpenPhish: feed parsed as empty; keeping previous feed")
		return
	}
	openPhishMu.Lock()
	openPhishURLs = updated
	openPhishUpdated = time.Now()
	openPhishMu.Unlock()
	log.Printf("OpenPhish: loaded %d phishing URLs", len(updated))
}

func canonicalThreatURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return "", errors.New("empty or oversized URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("unsupported URL scheme")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" {
		return "", errors.New("invalid URL authority")
	}
	host, err := normalizeHost(parsed.Hostname())
	if err != nil {
		return "", err
	}
	parsed.Host = host
	if port := parsed.Port(); port != "" && !((parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443")) {
		parsed.Host = netJoinHostPort(host, port)
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String(), nil
}

// netJoinHostPort не требует net.JoinHostPort для обычного DNS имени, но
// корректно сохраняет скобки для IPv6.
func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func checkThreatIntel(ctx context.Context, rawURL string) ThreatIntelReport {
	report := ThreatIntelReport{Status: "unavailable", Providers: []string{}, Threats: []string{}, Reasons: []string{}}
	canonical, err := canonicalThreatURL(rawURL)
	if err != nil {
		return report
	}
	if cached, ok := getThreatCache(canonical); ok {
		return cached
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	available := 0
	googleConfigured := strings.TrimSpace(os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY")) != ""
	googleSucceeded := false
	googleTTL := time.Duration(0)
	hit := false

	openPhishMu.RLock()
	_, openHit := openPhishURLs[canonical]
	feedReady := !openPhishUpdated.IsZero()
	openPhishMu.RUnlock()
	if feedReady {
		available++
		report.Providers = append(report.Providers, "OpenPhish")
		if openHit {
			hit = true
			report.Threats = append(report.Threats, "PHISHING")
			report.Reasons = append(report.Reasons, "URL найдена в OpenPhish Community Feed.")
		}
	}

	apiKey := strings.TrimSpace(os.Getenv("GOOGLE_SAFE_BROWSING_API_KEY"))
	if apiKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			googleCtx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
			defer cancel()
			matches, ttl, err := checkGoogleSafeBrowsing(googleCtx, canonical, apiKey)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("Google Safe Browsing: lookup failed: %v", err)
				return
			}
			googleSucceeded = true
			googleTTL = ttl
			available++
			report.Providers = append(report.Providers, "Google Safe Browsing")
			if len(matches) > 0 {
				hit = true
				report.Threats = append(report.Threats, matches...)
				report.Reasons = append(report.Reasons, "Возможная угроза: URL обнаружена Google Safe Browsing. Advisory provided by Google: https://developers.google.com/safe-browsing/.")
			}
		}()
	}
	wg.Wait()

	switch {
	case hit:
		report.Status = "hit"
	case available == 0:
		report.Status = "unavailable"
	case googleConfigured && !googleSucceeded:
		report.Status = "partial"
	case googleConfigured && !feedReady:
		report.Status = "partial"
	default:
		report.Status = "clean"
	}

	// Кэшируем только в пределах срока актуальности ответа Google. Для локального
	// OpenPhish-снимка используем короткий TTL, не связанный с TTL Google.
	cacheTTL := 2 * time.Minute
	if googleSucceeded && googleTTL > 0 && googleTTL < cacheTTL {
		cacheTTL = googleTTL
	}
	if googleConfigured && googleSucceeded && googleTTL <= 0 {
		cacheTTL = 0
	}
	if (report.Status == "hit" || report.Status == "clean") && cacheTTL > 0 {
		putThreatCache(canonical, report, cacheTTL)
	}
	return report
}

func checkGoogleSafeBrowsing(ctx context.Context, targetURL, apiKey string) ([]string, time.Duration, error) {
	endpoint, err := url.Parse(googleSafeBrowsingURL)
	if err != nil {
		return nil, 0, err
	}
	query := endpoint.Query()
	query.Set("key", apiKey)
	query.Add("urls", targetURL)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PhishDetector/1.0")
	resp, err := threatHTTPClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, 0, fmt.Errorf("Google Safe Browsing returned %s: %s", resp.Status, strings.TrimSpace(string(limited)))
	}
	var decoded googleThreatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&decoded); err != nil {
		return nil, 0, err
	}
	ttl, err := time.ParseDuration(decoded.CacheDuration)
	if err != nil || ttl <= 0 {
		ttl = 0 // не кэшируем ответ Google без корректного cacheDuration
	}
	matches := make([]string, 0, len(decoded.Threats))
	for _, threat := range decoded.Threats {
		for _, threatType := range threat.ThreatTypes {
			if threatType != "" {
				matches = append(matches, threatType)
			}
		}
	}
	return matches, ttl, nil
}

func getThreatCache(key string) (ThreatIntelReport, bool) {
	threatCacheMu.Lock()
	defer threatCacheMu.Unlock()
	entry, ok := threatCache[key]
	if !ok {
		return ThreatIntelReport{}, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(threatCache, key)
		return ThreatIntelReport{}, false
	}
	return entry.report, true
}

func putThreatCache(key string, report ThreatIntelReport, ttl time.Duration) {
	threatCacheMu.Lock()
	defer threatCacheMu.Unlock()
	if len(threatCache) >= threatIntelCacheMax {
		for k, v := range threatCache {
			if time.Now().After(v.expiresAt) {
				delete(threatCache, k)
			}
		}
		if len(threatCache) >= threatIntelCacheMax {
			// Eviction is intentionally simple and bounded; cache order is not semantic.
			for k := range threatCache {
				delete(threatCache, k)
				break
			}
		}
	}
	put := ThreatIntelReport{
		Status:    report.Status,
		Providers: append([]string(nil), report.Providers...),
		Threats:   append([]string(nil), report.Threats...),
		Reasons:   append([]string(nil), report.Reasons...),
	}
	threatCache[key] = threatCacheEntry{report: put, expiresAt: time.Now().Add(ttl)}
}
