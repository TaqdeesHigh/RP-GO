package main

import (
	"flag"
	"log"

	"RP-GO/cmd/proxy/commands"
	"RP-GO/internal/config"
)

func main() {
	// Define all flags in main
	configFile := flag.String("config", config.DefaultConfigFile, "Path to config file")
	listenAddr := flag.String("listen", "", "Address to listen on (overrides config file)")
	targetURL := flag.String("target", "", "Target URL to proxy to (overrides config file)")
	logFile := flag.String("log", "", "Log file path (overrides config file)")
	blacklistFile := flag.String("blacklist", "", "Path to blacklist file (overrides config file)")
	certFile := flag.String("cert", "", "Path to TLS certificate file (overrides config file)")
	keyFile := flag.String("key", "", "Path to TLS key file (overrides config file)")
	requestsPerMin := flag.Int("rate", 0, "Maximum requests per minute per IP (overrides config file)")
	enableMetrics := flag.Bool("metrics", true, "Enable request metrics (overrides config file)")

	// Parse all flags
	flag.Parse()

	// Create command options struct to pass all flags
	options := commands.ServerOptions{
		ConfigFile:     *configFile,
		ListenAddr:     *listenAddr,
		TargetURL:      *targetURL,
		LogFile:        *logFile,
		BlacklistFile:  *blacklistFile,
		CertFile:       *certFile,
		KeyFile:        *keyFile,
		RequestsPerMin: *requestsPerMin,
		EnableMetrics:  *enableMetrics,
	}

	// Run the server with all options
	if err := commands.RunServer(options); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
