package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultConfigFile = "proxy.properties.json"
)

// Config holds the proxy server configuration
type Config struct {
	ListenAddr     string
	TargetURL      string
	LogFile        string
	BlacklistFile  string
	CertFile       string
	KeyFile        string
	RequestsPerMin int
	EnableMetrics  bool
}

// PathRoute defines a path-based routing rule
type PathRoute struct {
	PathPrefix string
	TargetURL  string
}

// SetDefaults sets default values for any unspecified config options
func SetDefaults(cfg *Config) {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.TargetURL == "" {
		cfg.TargetURL = "http://localhost:8000"
	}
	if cfg.BlacklistFile == "" {
		cfg.BlacklistFile = "blacklist.json"
	}
	if cfg.RequestsPerMin == 0 {
		cfg.RequestsPerMin = 60
	}
}

// SaveConfig writes the current configuration to a JSON file
func SaveConfig(cfg Config, routes []PathRoute, filename string) error {
	if filename == "" {
		filename = DefaultConfigFile
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create config directory: %v", err)
		}
	}

	// Format config for saving
	configToSave := map[string]interface{}{
		"listenAddr":     cfg.ListenAddr,
		"targetURL":      cfg.TargetURL,
		"logFile":        cfg.LogFile,
		"blacklistFile":  cfg.BlacklistFile,
		"certFile":       cfg.CertFile,
		"keyFile":        cfg.KeyFile,
		"requestsPerMin": cfg.RequestsPerMin,
		"enableMetrics":  cfg.EnableMetrics,
	}

	// Save routes too
	routesToSave := make([]map[string]string, 0)
	for _, route := range routes {
		routesToSave = append(routesToSave, map[string]string{
			"pathPrefix": route.PathPrefix,
			"targetURL":  route.TargetURL,
		})
	}
	configToSave["routes"] = routesToSave

	data, err := json.MarshalIndent(configToSave, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// LoadConfig loads the configuration from a JSON file
func LoadConfig(filename string) (Config, []PathRoute, error) {
	if filename == "" {
		filename = DefaultConfigFile
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default config if file doesn't exist
			return Config{
				ListenAddr:     ":8080",
				TargetURL:      "http://localhost:8000",
				BlacklistFile:  "blacklist.json",
				RequestsPerMin: 60,
				EnableMetrics:  true,
			}, nil, nil
		}
		return Config{}, nil, err
	}

	var loadedConfig map[string]interface{}
	if err := json.Unmarshal(data, &loadedConfig); err != nil {
		return Config{}, nil, err
	}

	config := Config{}

	// Extract basic config values
	if v, ok := loadedConfig["listenAddr"].(string); ok {
		config.ListenAddr = v
	}
	if v, ok := loadedConfig["targetURL"].(string); ok {
		config.TargetURL = v
	}
	if v, ok := loadedConfig["logFile"].(string); ok {
		config.LogFile = v
	}
	if v, ok := loadedConfig["blacklistFile"].(string); ok {
		config.BlacklistFile = v
	}
	if v, ok := loadedConfig["certFile"].(string); ok {
		config.CertFile = v
	}
	if v, ok := loadedConfig["keyFile"].(string); ok {
		config.KeyFile = v
	}
	if v, ok := loadedConfig["requestsPerMin"].(float64); ok {
		config.RequestsPerMin = int(v)
	}
	if v, ok := loadedConfig["enableMetrics"].(bool); ok {
		config.EnableMetrics = v
	}

	// Extract routes
	var routes []PathRoute
	if routesData, ok := loadedConfig["routes"].([]interface{}); ok {
		for _, routeData := range routesData {
			if routeMap, ok := routeData.(map[string]interface{}); ok {
				pathPrefix, _ := routeMap["pathPrefix"].(string)
				targetURL, _ := routeMap["targetURL"].(string)
				if pathPrefix != "" && targetURL != "" {
					routes = append(routes, PathRoute{
						PathPrefix: pathPrefix,
						TargetURL:  targetURL,
					})
				}
			}
		}
	}

	return config, routes, nil
}
