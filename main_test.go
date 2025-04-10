// main_test.go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestReverseProxy(t *testing.T) {
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Test headers are forwarded
		proxyTime := r.Header.Get("X-Proxy-Time")
		if proxyTime == "" {
			t.Error("X-Proxy-Time header not set")
		}

		forwardedBy := r.Header.Get("X-Forwarded-By")
		if forwardedBy != "go-reverse-proxy" {
			t.Errorf("Expected X-Forwarded-By to be 'go-reverse-proxy', got '%s'", forwardedBy)
		}

		// Echo request details
		fmt.Fprintf(w, "Path: %s\nMethod: %s\nQuery: %s",
			r.URL.Path,
			r.Method,
			r.URL.RawQuery)
	}))
	defer backendServer.Close()

	// Create the reverse proxy
	config := Config{
		ListenAddr:     ":8080", // Not used in test
		TargetURL:      backendServer.URL,
		BlacklistFile:  "test_blacklist.json",
		RequestsPerMin: 60,
		EnableMetrics:  true,
	}

	proxy, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Add a route
	proxy.AddRoute("/", backendServer.URL)

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()

	// Test cases
	testCases := []struct {
		method string
		path   string
		query  string
	}{
		{"GET", "/api/users", "page=1&size=10"},
		{"POST", "/api/data", ""},
		{"DELETE", "/api/resources/123", ""},
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s %s", tc.method, tc.path), func(t *testing.T) {
			// Create the request
			url := proxyServer.URL + tc.path
			if tc.query != "" {
				url += "?" + tc.query
			}

			req, err := http.NewRequest(tc.method, url, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// Execute the request
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			// Check the response
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			// Check response body
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			// Basic verification of response content
			expectedPath := tc.path
			if string(body) == "" || !contains(string(body), expectedPath) {
				t.Errorf("Response doesn't contain expected path '%s': %s", expectedPath, body)
			}
		})
	}

	// Clean up test blacklist file if it exists
	if _, err := os.Stat(config.BlacklistFile); err == nil {
		os.Remove(config.BlacklistFile)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr || len(s) > 0 && contains(s[1:], substr)
}

func TestProxyErrorHandling(t *testing.T) {
	// Create a configuration with a deliberately invalid target URL
	config := Config{
		ListenAddr:     ":8080",
		TargetURL:      "http://nonexistent.example.com",
		BlacklistFile:  "test_blacklist.json",
		RequestsPerMin: 60,
		EnableMetrics:  true,
	}

	proxy, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Add a route
	proxy.AddRoute("/", config.TargetURL)

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()

	// Make a request to the proxy
	resp, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify we get a 502 Bad Gateway error
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", resp.StatusCode)
	}

	// Clean up test blacklist file if it exists
	if _, err := os.Stat(config.BlacklistFile); err == nil {
		os.Remove(config.BlacklistFile)
	}
}

func TestBlacklisting(t *testing.T) {
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer backendServer.Close()

	// Create the reverse proxy
	config := Config{
		ListenAddr:     ":8080",
		TargetURL:      backendServer.URL,
		BlacklistFile:  "test_blacklist.json",
		RequestsPerMin: 60,
		EnableMetrics:  true,
	}

	proxy, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Add a route
	proxy.AddRoute("/", backendServer.URL)

	// Add test IP to blacklist
	testIP := "192.168.1.1"
	proxy.BlacklistIP(testIP, "Testing blacklist", 0) // Permanent blacklist

	// Verify IP is blacklisted
	if !proxy.IsBlacklisted(testIP) {
		t.Errorf("Expected IP %s to be blacklisted", testIP)
	}

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()

	// Create a test request with the blacklisted IP
	req, _ := http.NewRequest("GET", proxyServer.URL, nil)
	req.Header.Set("X-Forwarded-For", testIP)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check that the request was blocked
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected status 403 Forbidden for blacklisted IP, got %d", resp.StatusCode)
	}

	// Test removing from blacklist
	proxy.RemoveFromBlacklist(testIP)
	if proxy.IsBlacklisted(testIP) {
		t.Errorf("IP %s should have been removed from blacklist", testIP)
	}

	// Test temporary blacklisting
	tempIP := "10.0.0.1"
	proxy.BlacklistIP(tempIP, "Testing temporary blacklist", 50*time.Millisecond)

	// Should be blacklisted initially
	if !proxy.IsBlacklisted(tempIP) {
		t.Errorf("Expected IP %s to be temporarily blacklisted", tempIP)
	}

	// Wait for blacklist to expire
	time.Sleep(100 * time.Millisecond)

	// Should no longer be blacklisted
	if proxy.IsBlacklisted(tempIP) {
		t.Errorf("IP %s should no longer be blacklisted after expiration", tempIP)
	}

	// Test saving and loading blacklist
	newIP := "172.16.0.1"
	proxy.BlacklistIP(newIP, "Testing save/load", 0)

	err = proxy.SaveBlacklist(config.BlacklistFile)
	if err != nil {
		t.Fatalf("Failed to save blacklist: %v", err)
	}

	// Create a new proxy instance and load the blacklist
	newProxy, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create new proxy: %v", err)
	}

	err = newProxy.LoadBlacklist(config.BlacklistFile)
	if err != nil {
		t.Fatalf("Failed to load blacklist: %v", err)
	}

	// Check if the loaded blacklist contains our IP
	if !newProxy.IsBlacklisted(newIP) {
		t.Errorf("Expected IP %s to be in loaded blacklist", newIP)
	}

	// Clean up test blacklist file
	if _, err := os.Stat(config.BlacklistFile); err == nil {
		os.Remove(config.BlacklistFile)
	}
}

func TestRateLimiting(t *testing.T) {
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	}))
	defer backendServer.Close()

	// Create the reverse proxy with a very low rate limit for testing
	config := Config{
		ListenAddr:     ":8080",
		TargetURL:      backendServer.URL,
		RequestsPerMin: 2, // Very low for testing
		EnableMetrics:  true,
	}

	proxy, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Add a route
	proxy.AddRoute("/", backendServer.URL)

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()

	// Create a client
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Test IP for rate limiting
	testIP := "192.168.1.2"

	// First request should succeed
	req1, _ := http.NewRequest("GET", proxyServer.URL, nil)
	req1.Header.Set("X-Forwarded-For", testIP)

	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	defer resp1.Body.Close()

	if resp1.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for first request, got %d", resp1.StatusCode)
	}

	// Second request should succeed (because we allow burst of 5)
	req2, _ := http.NewRequest("GET", proxyServer.URL, nil)
	req2.Header.Set("X-Forwarded-For", testIP)

	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("Second request failed: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for second request, got %d", resp2.StatusCode)
	}

	// Let's make many requests to exceed the burst limit
	for i := 0; i < 6; i++ {
		req, _ := http.NewRequest("GET", proxyServer.URL, nil)
		req.Header.Set("X-Forwarded-For", testIP)

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()
	}

	// Now we should hit the rate limit
	reqLimited, _ := http.NewRequest("GET", proxyServer.URL, nil)
	reqLimited.Header.Set("X-Forwarded-For", testIP)

	respLimited, err := client.Do(reqLimited)
	if err != nil {
		t.Fatalf("Rate-limited request failed: %v", err)
	}
	defer respLimited.Body.Close()

	if respLimited.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 Too Many Requests for rate-limited request, got %d", respLimited.StatusCode)
	}
}

func TestPathRouting(t *testing.T) {
	// Create two test backend servers
	backendServer1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Backend 1"))
	}))
	defer backendServer1.Close()

	backendServer2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Backend 2"))
	}))
	defer backendServer2.Close()

	// Create the reverse proxy with higher request limit for tests
	config := Config{
		ListenAddr:     ":8080",
		TargetURL:      backendServer1.URL, // Default target
		RequestsPerMin: 100,                // Higher limit for tests
	}

	proxy, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Add routes
	proxy.AddRoute("/", backendServer1.URL)
	proxy.AddRoute("/api/", backendServer2.URL)
	proxy.AddRoute("/api/v2/", backendServer1.URL) // More specific path should override /api/

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()

	// Test cases for path routing
	tests := []struct {
		path           string
		expectedResult string
	}{
		{"/", "Backend 1"},
		{"/home", "Backend 1"},
		{"/api/users", "Backend 2"},
		{"/api/data", "Backend 2"},
		{"/api/v2/users", "Backend 1"}, // Should go to backend1
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			url := proxyServer.URL + test.path
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			// Add header to skip rate limiting for test
			req.Header.Set("X-Test-Skip-Rate-Limit", "true")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200, got %d", resp.StatusCode)
			}

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}

			if string(body) != test.expectedResult {
				t.Errorf("Expected body '%s', got '%s'", test.expectedResult, string(body))
			}
		})
	}

	// Test route removal
	proxy.RemoveRoute("/api/")

	// Reset rate limiters before testing route removal
	proxy.rateLimiterMutex.Lock()
	proxy.rateLimiters = make(map[string]*rate.Limiter)
	proxy.rateLimiterMutex.Unlock()

	// Now requests to /api/ (but not /api/v2/) should go to the default route
	req, err := http.NewRequest("GET", proxyServer.URL+"/api/users", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Add header to skip rate limiting for test
	req.Header.Set("X-Test-Skip-Rate-Limit", "true")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "Backend 1" {
		t.Errorf("Expected body 'Backend 1' after route removal, got '%s'", string(body))
	}
}

func TestMetrics(t *testing.T) {
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/error" {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.Write([]byte("OK"))
		}
	}))
	defer backendServer.Close()

	// Create the reverse proxy with metrics enabled
	config := Config{
		ListenAddr:    ":8080",
		TargetURL:     backendServer.URL,
		EnableMetrics: true,
	}

	proxy, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Add a route
	proxy.AddRoute("/", backendServer.URL)

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxy.Handler())
	defer proxyServer.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Make some test requests
	client.Get(proxyServer.URL + "/path1")
	client.Get(proxyServer.URL + "/path2")
	client.Get(proxyServer.URL + "/error")

	// Blacklist an IP and try to access
	testIP := "10.0.0.5"
	proxy.BlacklistIP(testIP, "Testing metrics", 0)

	req, _ := http.NewRequest("GET", proxyServer.URL, nil)
	req.Header.Set("X-Forwarded-For", testIP)
	client.Do(req)

	// Get metrics
	metrics := proxy.GetMetrics()

	// Check basic metrics
	if metrics.RequestCount != 4 {
		t.Errorf("Expected 4 requests, got %d", metrics.RequestCount)
	}

	if metrics.StatusCodes[http.StatusOK] != 2 {
		t.Errorf("Expected 2 OK responses, got %d", metrics.StatusCodes[http.StatusOK])
	}

	if metrics.StatusCodes[http.StatusInternalServerError] != 1 {
		t.Errorf("Expected 1 error response, got %d", metrics.StatusCodes[http.StatusInternalServerError])
	}

	if metrics.BlacklistedRequests != 1 {
		t.Errorf("Expected 1 blacklisted request, got %d", metrics.BlacklistedRequests)
	}

	// Test metrics reset
	proxy.ResetMetrics()
	resetMetrics := proxy.GetMetrics()

	if resetMetrics.RequestCount != 0 {
		t.Errorf("Expected 0 requests after reset, got %d", resetMetrics.RequestCount)
	}
}
