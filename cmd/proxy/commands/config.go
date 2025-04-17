package commands

import (
	"flag"
	"fmt"

	"RP-GO/internal/config"
)

// SaveConfig saves the current configuration to the specified file
func SaveConfig(configFilePath string) error {
	// Parse command line flags
	listenAddr := flag.String("listen", "", "Address to listen on")
	targetURL := flag.String("target", "", "Target URL to proxy to")
	logFile := flag.String("log", "", "Log file path")
	blacklistFile := flag.String("blacklist", "", "Path to blacklist file")
	certFile := flag.String("cert", "", "Path to TLS certificate file")
	keyFile := flag.String("key", "", "Path to TLS key file")
	requestsPerMin := flag.Int("rate", 0, "Maximum requests per minute per IP")
	enableMetrics := flag.Bool("metrics", true, "Enable request metrics")
	flag.Parse()

	// Create config with provided values
	cfg := config.Config{
		ListenAddr:     *listenAddr,
		TargetURL:      *targetURL,
		LogFile:        *logFile,
		BlacklistFile:  *blacklistFile,
		CertFile:       *certFile,
		KeyFile:        *keyFile,
		RequestsPerMin: *requestsPerMin,
		EnableMetrics:  *enableMetrics,
	}

	// Set defaults for any missing values
	config.SetDefaults(&cfg)

	// Save the config to file
	return config.SaveConfig(cfg, nil, configFilePath)
}

// ShowConfig displays the current configuration
func ShowConfig(configFilePath string) error {
	// Load config from file
	cfg, routes, err := config.LoadConfig(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}

	// Print configuration
	fmt.Printf("Current Configuration:\n")
	fmt.Printf("Listen Address: %s\n", cfg.ListenAddr)
	fmt.Printf("Target URL: %s\n", cfg.TargetURL)
	fmt.Printf("Log File: %s\n", cfg.LogFile)
	fmt.Printf("Blacklist File: %s\n", cfg.BlacklistFile)
	fmt.Printf("TLS Certificate: %s\n", cfg.CertFile)
	fmt.Printf("TLS Key: %s\n", cfg.KeyFile)
	fmt.Printf("Rate Limit: %d requests/min\n", cfg.RequestsPerMin)
	fmt.Printf("Metrics Enabled: %v\n", cfg.EnableMetrics)

	// Print routes
	if len(routes) > 0 {
		fmt.Printf("\nRoutes:\n")
		for i, route := range routes {
			fmt.Printf("%d. %s -> %s\n", i+1, route.PathPrefix, route.TargetURL)
		}
	}

	return nil
}
