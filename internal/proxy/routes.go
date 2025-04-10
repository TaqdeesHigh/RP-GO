package proxy

import (
	"strings"

	"RP-GO/internal/config"
)

// AddRoute adds a path-based routing rule
func (p *ReverseProxy) AddRoute(pathPrefix, targetURL string) {
	p.RoutesMutex.Lock()
	defer p.RoutesMutex.Unlock()

	// Remove duplicate routes with the same path prefix
	for i, route := range p.Routes {
		if route.PathPrefix == pathPrefix {
			p.Routes = append(p.Routes[:i], p.Routes[i+1:]...)
			break
		}
	}

	// Add new route (longer paths first to ensure specific paths match before general ones)
	newRoute := config.PathRoute{
		PathPrefix: pathPrefix,
		TargetURL:  targetURL,
	}

	inserted := false
	for i, route := range p.Routes {
		if len(newRoute.PathPrefix) > len(route.PathPrefix) {
			// Insert the new route at this position
			p.Routes = append(p.Routes[:i], append([]config.PathRoute{newRoute}, p.Routes[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		p.Routes = append(p.Routes, newRoute)
	}

	p.Logger.Printf("Added route: %s -> %s", pathPrefix, targetURL)
}

// RemoveRoute removes a routing rule
func (p *ReverseProxy) RemoveRoute(pathPrefix string) {
	p.RoutesMutex.Lock()
	defer p.RoutesMutex.Unlock()

	for i, route := range p.Routes {
		if route.PathPrefix == pathPrefix {
			p.Routes = append(p.Routes[:i], p.Routes[i+1:]...)
			p.Logger.Printf("Removed route: %s", pathPrefix)
			return
		}
	}
}

// findRouteForPath returns the target URL for the given path
func (p *ReverseProxy) findRouteForPath(path string) string {
	p.RoutesMutex.RLock()
	defer p.RoutesMutex.RUnlock()

	for _, route := range p.Routes {
		if strings.HasPrefix(path, route.PathPrefix) {
			return route.TargetURL
		}
	}

	// If we have no routes or no match, return empty string
	return ""
}

// GetRoutes returns all configured routes
func (p *ReverseProxy) GetRoutes() []config.PathRoute {
	p.RoutesMutex.RLock()
	defer p.RoutesMutex.RUnlock()

	routes := make([]config.PathRoute, len(p.Routes))
	copy(routes, p.Routes)
	return routes
}
