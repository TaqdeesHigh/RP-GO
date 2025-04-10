package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"RP-GO/internal/config"
	"RP-GO/internal/proxy"
)

func main() {
	// Parse command line flags
	configFile := flag.String("config", config.DefaultConfigFile, "Path to config file")
	listenAddr := flag.String("listen", "", "Address to listen on (overrides config file)")
	targetURL := flag.String("target", "", "Target URL to proxy to (overrides config file)")
	logFile := flag.String("log", "", "Log file path (overrides config file)")
	blacklistFile := flag.String("blacklist", "", "Path to blacklist file (overrides config file)")
	certFile := flag.String("cert", "", "Path to TLS certificate file (overrides config file)")
	keyFile := flag.String("key", "", "Path to TLS key file (overrides config file)")
	requestsPerMin := flag.Int("rate", 0, "Maximum requests per minute per IP (overrides config file)")
	enableMetrics := flag.Bool("metrics", true, "Enable request metrics (overrides config file)")
	flag.Parse()

	// Load config from file
	cfg, routes, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Printf("Warning: Failed to load config file: %v, using defaults and command line args", err)
	}

	// Override config with command line arguments if provided
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *targetURL != "" {
		cfg.TargetURL = *targetURL
	}
	if *logFile != "" {
		cfg.LogFile = *logFile
	}
	if *blacklistFile != "" {
		cfg.BlacklistFile = *blacklistFile
	}
	if *certFile != "" {
		cfg.CertFile = *certFile
	}
	if *keyFile != "" {
		cfg.KeyFile = *keyFile
	}
	if *requestsPerMin != 0 {
		cfg.RequestsPerMin = *requestsPerMin
	}
	if !*enableMetrics {
		cfg.EnableMetrics = *enableMetrics
	}

	// Use defaults for any unspecified values
	config.SetDefaults(&cfg)

	// Create and start the proxy server
	reverseProxy, err := proxy.NewReverseProxy(cfg)
	if err != nil {
		log.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Add routes from config
	if len(routes) > 0 {
		for _, route := range routes {
			reverseProxy.AddRoute(route.PathPrefix, route.TargetURL)
		}
	} else {
		// Add default route if no routes were loaded
		reverseProxy.AddRoute("/", cfg.TargetURL)
	}

	// Save the current configuration
	if err := reverseProxy.SaveConfig(*configFile); err != nil {
		reverseProxy.Logger.Printf("Warning: Failed to save config file: %v", err)
	}

	// Start periodic save (every 5 minutes)
	reverseProxy.StartPeriodicSave(*configFile, 5*time.Minute)

	// Setup a shutdown handler
	reverseProxy.SetupCleanupHandler(*configFile)

	// Create HTTP server
	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: reverseProxy.Handler(),
	}

	// Start server with or without TLS
	reverseProxy.Logger.Printf("Starting reverse proxy server on %s -> %s", cfg.ListenAddr, cfg.TargetURL)
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		reverseProxy.Logger.Printf("TLS enabled with cert: %s, key: %s", cfg.CertFile, cfg.KeyFile)
		log.Fatal(server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}
