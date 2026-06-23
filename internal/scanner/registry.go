package scanner

import (
	"sort"
	"sync"
)

// Registry holds all enabled ServiceScanners. It is safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	scanners map[string]ServiceScanner
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{scanners: map[string]ServiceScanner{}}
}

// Register adds a scanner. Names must be unique — duplicates overwrite.
func (r *Registry) Register(s ServiceScanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[s.Name()] = s
}

// All returns scanners in deterministic name order.
func (r *Registry) All() []ServiceScanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.scanners))
	for n := range r.scanners {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]ServiceScanner, 0, len(names))
	for _, n := range names {
		out = append(out, r.scanners[n])
	}
	return out
}

// Names returns sorted scanner names.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.scanners))
	for n := range r.scanners {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Len returns the number of registered scanners.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.scanners)
}
