package blacklist

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// BlacklistEntry represents a blacklisted IP with optional expiration
type BlacklistEntry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // Zero time means permanent ban
}

// Blacklist manages IP blacklisting functionality
type Blacklist struct {
	entries map[string]BlacklistEntry
	mutex   sync.RWMutex
}

// New creates a new blacklist instance
func New() *Blacklist {
	return &Blacklist{
		entries: make(map[string]BlacklistEntry),
	}
}

// Load loads blacklisted IPs from a file
func (b *Blacklist) Load(filename string) error {
	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var entries []BlacklistEntry
	if err := json.Unmarshal(file, &entries); err != nil {
		return err
	}

	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Clear previous entries
	b.entries = make(map[string]BlacklistEntry)

	// Add new entries, filtering out expired ones
	now := time.Now()
	for _, entry := range entries {
		// Skip expired entries
		if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
			continue
		}
		b.entries[entry.IP] = entry
	}

	return nil
}

// Save saves the current blacklist to a file
func (b *Blacklist) Save(filename string) error {
	b.mutex.RLock()
	entries := make([]BlacklistEntry, 0, len(b.entries))
	for _, entry := range b.entries {
		entries = append(entries, entry)
	}
	b.mutex.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

// IsBlacklisted checks if an IP is blacklisted
func (b *Blacklist) IsBlacklisted(ip string) bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	entry, exists := b.entries[ip]
	if !exists {
		return false
	}

	// Check if the entry is expired
	if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(time.Now()) {
		return false
	}

	return true
}

// Add adds an IP to the blacklist
func (b *Blacklist) Add(ip, reason string, duration time.Duration) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	entry := BlacklistEntry{
		IP:        ip,
		Reason:    reason,
		CreatedAt: time.Now(),
	}

	// Set expiration time if duration is specified
	if duration > 0 {
		entry.ExpiresAt = entry.CreatedAt.Add(duration)
	}

	b.entries[ip] = entry
}

// Remove removes an IP from the blacklist
func (b *Blacklist) Remove(ip string) bool {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if _, exists := b.entries[ip]; exists {
		delete(b.entries, ip)
		return true
	}
	return false
}

// GetAll returns all blacklist entries
func (b *Blacklist) GetAll() []BlacklistEntry {
	b.mutex.RLock()
	defer b.mutex.RUnlock()

	entries := make([]BlacklistEntry, 0, len(b.entries))
	for _, entry := range b.entries {
		entries = append(entries, entry)
	}
	return entries
}

// Count returns the number of blacklisted IPs
func (b *Blacklist) Count() int {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return len(b.entries)
}
