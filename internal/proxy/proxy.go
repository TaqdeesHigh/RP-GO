package proxy

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"

	"RP-GO/internal/blacklist"
	"RP-GO/internal/config"
	"RP-GO/internal/metrics"
)

// ReverseProxy manages the proxy server
type ReverseProxy struct {
	Config           config.Config
	Blacklist        *blacklist.Blacklist
	Metrics          *metrics.Metrics
	Routes           []config.PathRoute
	RoutesMutex      sync.RWMutex
	RateLimiters     map[string]*rate.Limiter
	RateLimiterMutex sync.RWMutex
	Logger           *log.Logger
}

// NewReverseProxy creates a new reverse proxy instance
func NewReverseProxy(cfg config.Config) (*ReverseProxy, error) {
	// Setup logger
	var logWriter io.Writer = os.Stdout
	if cfg.LogFile != "" {
		// Create directory if it doesn't exist
		logDir := filepath.Dir(cfg.LogFile)
		if logDir != "." {
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create log directory: %v", err)
			}
		}

		file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logWriter = file
	}

	logger := log.New(logWriter, "[PROXY] ", log.LstdFlags)

	proxy := &ReverseProxy{
		Config:       cfg,
		Blacklist:    blacklist.New(),
		RateLimiters: make(map[string]*rate.Limiter),
		Routes:       []config.PathRoute{},
		Logger:       logger,
		Metrics:      metrics.New(),
	}

	// Load blacklist if file exists
	if _, err := os.Stat(cfg.BlacklistFile); err == nil {
		if err := proxy.Blacklist.Load(cfg.BlacklistFile); err != nil {
			return nil, fmt.Errorf("failed to load blacklist: %v", err)
		}
		logger.Printf("Loaded %d blacklist entries", proxy.Blacklist.Count())
	} else {
		logger.Printf("Blacklist file not found, creating a new one on shutdown")
	}

	return proxy, nil
}

// SaveConfig saves the current configuration
func (p *ReverseProxy) SaveConfig(filename string) error {
	p.RoutesMutex.RLock()
	routes := make([]config.PathRoute, len(p.Routes))
	copy(routes, p.Routes)
	p.RoutesMutex.RUnlock()

	err := config.SaveConfig(p.Config, routes, filename)
	if err == nil {
		p.Logger.Printf("Configuration saved to %s", filename)
	}
	return err
}

// StartPeriodicSave starts a goroutine that periodically saves configuration and blacklist
func (p *ReverseProxy) StartPeriodicSave(configFile string, interval time.Duration) {
	if interval == 0 {
		interval = 5 * time.Minute // Default to 5 minutes
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			<-ticker.C
			p.Logger.Printf("Performing periodic save of configuration and blacklist...")

			// Save config
			if err := p.SaveConfig(configFile); err != nil {
				p.Logger.Printf("Error saving config: %v", err)
			}

			// Save blacklist
			if p.Config.BlacklistFile != "" {
				if err := p.Blacklist.Save(p.Config.BlacklistFile); err != nil {
					p.Logger.Printf("Error saving blacklist: %v", err)
				}
			}
		}
	}()
}

// SetupCleanupHandler ensures resources are properly closed on shutdown
func (p *ReverseProxy) SetupCleanupHandler(configFile string) {
	// Create a channel for OS signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		p.Logger.Printf("Shutdown initiated, saving configuration and blacklist...")

		// Save config
		if err := p.SaveConfig(configFile); err != nil {
			p.Logger.Printf("Error saving config: %v", err)
		}

		// Save blacklist
		if p.Config.BlacklistFile != "" {
			if err := p.Blacklist.Save(p.Config.BlacklistFile); err != nil {
				p.Logger.Printf("Error saving blacklist: %v", err)
			}
		}

		os.Exit(0)
	}()
}

// getRateLimiter returns a rate limiter for the given IP
func (p *ReverseProxy) getRateLimiter(ip string) *rate.Limiter {
	p.RateLimiterMutex.RLock()
	limiter, exists := p.RateLimiters[ip]
	p.RateLimiterMutex.RUnlock()

	if !exists {
		limiter = rate.NewLimiter(rate.Limit(p.Config.RequestsPerMin)/60, 5) // Allow burst of 5

		p.RateLimiterMutex.Lock()
		p.RateLimiters[ip] = limiter
		p.RateLimiterMutex.Unlock()
	}

	return limiter
}

// checkRateLimit checks if the request is within rate limits
func (p *ReverseProxy) checkRateLimit(ip string) bool {
	limiter := p.getRateLimiter(ip)
	return limiter.Allow()
}
