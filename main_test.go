// main_test.go
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
		ListenAddr: ":8080", // Not used in test
		TargetURL:  backendServer.URL,
	}

	proxyHandler, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxyHandler)
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
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr || len(s) > 0 && contains(s[1:], substr)
}

func TestProxyErrorHandling(t *testing.T) {
	// Create a configuration with a deliberately invalid target URL
	config := Config{
		ListenAddr: ":8080",
		TargetURL:  "http://localhost",
	}

	proxyHandler, err := NewReverseProxy(config)
	if err != nil {
		t.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Create a test server using our proxy handler
	proxyServer := httptest.NewServer(proxyHandler)
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
}
