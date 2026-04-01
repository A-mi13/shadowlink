package browser

import (
	"math/rand/v2"
	"sync"
)

// Default URL pools that look like typical REST API endpoints.
var (
	defaultUploadPaths = []string{
		"/api/v2/events",
		"/api/v2/sync",
		"/api/metrics",
		"/graphql",
		"/api/v2/telemetry",
		"/api/v2/batch",
	}
	defaultDownloadPaths = []string{
		"/api/v2/feed",
		"/api/v2/notifications",
		"/api/content",
		"/api/v2/updates",
		"/api/v2/stream",
	}
)

// URLPool rotates through URL paths to avoid repetitive patterns visible to DPI.
type URLPool struct {
	uploadPaths   []string
	downloadPaths []string
	mu            sync.Mutex
}

// NewURLPool creates a pool with default API-like paths.
func NewURLPool() *URLPool {
	return &URLPool{
		uploadPaths:   defaultUploadPaths,
		downloadPaths: defaultDownloadPaths,
	}
}

// NewURLPoolCustom creates a pool with server-provided paths.
func NewURLPoolCustom(upload, download []string) *URLPool {
	if len(upload) == 0 {
		upload = defaultUploadPaths
	}
	if len(download) == 0 {
		download = defaultDownloadPaths
	}
	return &URLPool{
		uploadPaths:   upload,
		downloadPaths: download,
	}
}

// NextUploadPath returns a random upload URL path.
func (p *URLPool) NextUploadPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.uploadPaths[rand.IntN(len(p.uploadPaths))]
}

// NextDownloadPath returns a random download URL path.
func (p *URLPool) NextDownloadPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.downloadPaths[rand.IntN(len(p.downloadPaths))]
}

// UploadPaths returns all available upload paths.
func (p *URLPool) UploadPaths() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.uploadPaths))
	copy(out, p.uploadPaths)
	return out
}
