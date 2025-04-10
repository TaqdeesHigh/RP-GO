package metrics

import (
	"sync"
	"time"
)

// Metrics tracks usage statistics for the proxy
type Metrics struct {
	RequestCount        int64
	ErrorCount          int64
	TotalResponseTime   time.Duration
	StatusCodes         map[int]int64
	MethodCounts        map[string]int64
	RateLimitExceeded   int64
	BlacklistedRequests int64
	mutex               sync.RWMutex
}

// New creates a new metrics instance
func New() *Metrics {
	return &Metrics{
		StatusCodes:  make(map[int]int64),
		MethodCounts: make(map[string]int64),
	}
}

// Increment safely updates metrics
func (m *Metrics) Increment(updater func(*Metrics)) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	updater(m)
}

// Get returns a copy of the current metrics
func (m *Metrics) Get() Metrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Create a deep copy without copying the mutex
	metricsCopy := Metrics{
		RequestCount:        m.RequestCount,
		ErrorCount:          m.ErrorCount,
		TotalResponseTime:   m.TotalResponseTime,
		RateLimitExceeded:   m.RateLimitExceeded,
		BlacklistedRequests: m.BlacklistedRequests,
		StatusCodes:         make(map[int]int64),
		MethodCounts:        make(map[string]int64),
	}

	for status, count := range m.StatusCodes {
		metricsCopy.StatusCodes[status] = count
	}

	for method, count := range m.MethodCounts {
		metricsCopy.MethodCounts[method] = count
	}

	return metricsCopy
}

// Reset resets all metrics counters
func (m *Metrics) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.RequestCount = 0
	m.ErrorCount = 0
	m.TotalResponseTime = 0
	m.RateLimitExceeded = 0
	m.BlacklistedRequests = 0
	m.StatusCodes = make(map[int]int64)
	m.MethodCounts = make(map[string]int64)
}
