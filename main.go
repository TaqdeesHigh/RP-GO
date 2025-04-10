// main.go
package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// Config holds the proxy server configuration
type Config struct {
	ListenAddr string
	TargetURL  string
}

func main() {
	// Parse command line flags
	listenAddr := flag.String("listen", ":8080", "Address to listen on (default :8080)")
	targetURL := flag.String("target", "http://localhost:8000", "Target URL to proxy to")
	flag.Parse()

	config := Config{
		ListenAddr: *listenAddr,
		TargetURL:  *targetURL,
	}

	// Create and start the proxy server
	proxy, err := NewReverseProxy(config)
	if err != nil {
		log.Fatalf("Failed to create reverse proxy: %v", err)
	}

	log.Printf("Starting reverse proxy server on %s -> %s", config.ListenAddr, config.TargetURL)
	log.Fatal(http.ListenAndServe(config.ListenAddr, proxy))
}

// NewReverseProxy creates a new reverse proxy handler
func NewReverseProxy(config Config) (http.Handler, error) {
	targetURL, err := url.Parse(config.TargetURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize the director function to add headers
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Add("X-Forwarded-By", "go-reverse-proxy")
		req.Header.Add("X-Proxy-Time", time.Now().Format(time.RFC3339))
	}

	// Add error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Proxy Error: " + err.Error()))
	}

	// Wrap the proxy with middleware for logging
	return LoggingMiddleware(proxy), nil
}

// LoggingMiddleware logs all requests processed by the proxy
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Wrap response writer to capture status code
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		log.Printf("Completed request: %s %s - status: %d in %v", r.Method, r.URL.Path, rw.statusCode, duration)
	})
}

// responseWriter is a wrapper around http.ResponseWriter that captures the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before writing it
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
