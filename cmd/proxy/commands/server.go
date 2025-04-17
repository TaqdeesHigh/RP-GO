package commands

import (
	"log"
	"net/http"
	"time"

	"RP-GO/internal/config"
	"RP-GO/internal/proxy"
)

// ServerOptions holds all command line options for the server
type ServerOptions struct {
	ConfigFile     string
	ListenAddr     string
	TargetURL      string
	LogFile        string
	BlacklistFile  string
	CertFile       string
	KeyFile        string
	RequestsPerMin int
	EnableMetrics  bool
}

// RunServer loads config and starts the proxy server
func RunServer(options ServerOptions) error {
	// Load config from file
	cfg, routes, err := config.LoadConfig(options.ConfigFile)
	if err != nil {
		log.Printf("Warning: Failed to load config file: %v, using defaults and command line args", err)
	}

	// Override config with command line arguments if provided
	if options.ListenAddr != "" {
		cfg.ListenAddr = options.ListenAddr
	}
	if options.TargetURL != "" {
		cfg.TargetURL = options.TargetURL
	}
	if options.LogFile != "" {
		cfg.LogFile = options.LogFile
	}
	if options.BlacklistFile != "" {
		cfg.BlacklistFile = options.BlacklistFile
	}
	if options.CertFile != "" {
		cfg.CertFile = options.CertFile
	}
	if options.KeyFile != "" {
		cfg.KeyFile = options.KeyFile
	}
	if options.RequestsPerMin != 0 {
		cfg.RequestsPerMin = options.RequestsPerMin
	}
	if !options.EnableMetrics {
		cfg.EnableMetrics = options.EnableMetrics
	}

	// Use defaults for any unspecified values
	config.SetDefaults(&cfg)

	return startProxyServer(cfg, routes, options.ConfigFile)
}

// startProxyServer creates and starts the proxy server
func startProxyServer(cfg config.Config, routes []config.PathRoute, configFile string) error {
	reverseProxy, err := proxy.NewReverseProxy(cfg)
	if err != nil {
		return err
	}

	if len(routes) > 0 {
		for _, route := range routes {
			reverseProxy.AddRoute(route.PathPrefix, route.TargetURL)
		}
	} else {
		// Add default route if no routes were loaded
		reverseProxy.AddRoute("/", cfg.TargetURL)
	}

	if err := reverseProxy.SaveConfig(configFile); err != nil {
		reverseProxy.Logger.Printf("Warning: Failed to save config file: %v", err)
	}

	reverseProxy.StartPeriodicSave(configFile, 5*time.Minute)

	reverseProxy.SetupCleanupHandler(configFile)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: reverseProxy.Handler(),
	}

	reverseProxy.Logger.Printf("Starting reverse proxy server on %s -> %s", cfg.ListenAddr, cfg.TargetURL)
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		reverseProxy.Logger.Printf("TLS enabled with cert: %s, key: %s", cfg.CertFile, cfg.KeyFile)
		return server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	} else {
		return server.ListenAndServe()
	}
}
