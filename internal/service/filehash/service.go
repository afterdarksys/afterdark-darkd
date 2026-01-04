package filehash

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

const serviceName = "filehash"

// Config holds filehash service configuration
type Config struct {
	Enabled        bool          `yaml:"enabled"`
	WatchPaths     []string      `yaml:"watch_paths"`
	Recursive      bool          `yaml:"recursive"`
	RealTimeWatch  bool          `yaml:"realtime_watch"` // Use fsnotify for real-time monitoring
	ScanInterval   time.Duration `yaml:"scan_interval"`
	SyncInterval   time.Duration `yaml:"sync_interval"`
	APIEndpoint    string        `yaml:"api_endpoint"`
	APIKey         string        `yaml:"api_key"`
	LocalDBPath    string        `yaml:"local_db_path"`
	MaxFileSize    int64         `yaml:"max_file_size"` // Skip files larger than this
	IgnorePatterns []string      `yaml:"ignore_patterns"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:       false,
		WatchPaths:    []string{},
		Recursive:     true,
		RealTimeWatch: true, // Use fsnotify by default
		ScanInterval:  5 * time.Minute,
		SyncInterval:  1 * time.Minute,
		APIEndpoint:   "https://api.filehashes.io",
		LocalDBPath:   "/var/lib/afterdark/filehashes.db",
		MaxFileSize:   100 * 1024 * 1024, // 100MB default
		IgnorePatterns: []string{
			"*.tmp", "*.log", "*.swp", "*~",
			".git/*", ".svn/*", "node_modules/*",
		},
	}
}

// Service monitors files and tracks their hashes
type Service struct {
	config  *Config
	logger  *zap.Logger
	store   *LocalStore
	watcher *fsnotify.Watcher

	mu         sync.RWMutex
	running    bool
	fileHashes map[string]*FileRecord

	stopCh    chan struct{}
	doneCh    chan struct{}
	triggerCh chan struct{}

	// Stats
	filesScanned   int64
	hashesComputed int64
	changesFound   int64
	lastScanTime   time.Time
	lastSyncTime   time.Time

	// Real-time events
	fileEvents int64
}

// FileRecord represents a tracked file
type FileRecord struct {
	Path      string    `json:"path"`
	Filename  string    `json:"filename"`
	Size      int64     `json:"size"`
	ModTime   time.Time `json:"mod_time"`
	SHA256    string    `json:"sha256"`
	SHA1      string    `json:"sha1"`
	MD5       string    `json:"md5"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Synced    bool      `json:"synced"`
}

// New creates a new filehash service
func New(logger *zap.Logger) *Service {
	return &Service{
		config:     DefaultConfig(),
		logger:     logger.Named(serviceName),
		fileHashes: make(map[string]*FileRecord),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		triggerCh:  make(chan struct{}, 1),
	}
}

// Name returns the service name
func (s *Service) Name() string {
	return serviceName
}

// Configure updates service configuration
func (s *Service) Configure(config interface{}) error {
	cfg, ok := config.(*Config)
	if !ok {
		return fmt.Errorf("invalid config type for filehash service")
	}

	s.mu.Lock()
	s.config = cfg
	s.mu.Unlock()

	s.logger.Info("configuration updated",
		zap.Strings("watch_paths", cfg.WatchPaths),
		zap.Duration("scan_interval", cfg.ScanInterval),
	)

	return nil
}

// Start initializes and starts the service
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("service already running")
	}

	if !s.config.Enabled {
		s.mu.Unlock()
		s.logger.Info("filehash service disabled")
		return nil
	}

	// Initialize local store
	store, err := NewLocalStore(s.config.LocalDBPath)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("initialize local store: %w", err)
	}
	s.store = store

	// Load existing records
	records, err := s.store.LoadAll()
	if err != nil {
		s.logger.Warn("failed to load existing records", zap.Error(err))
	} else {
		for _, r := range records {
			s.fileHashes[r.Path] = r
		}
		s.logger.Info("loaded existing file records", zap.Int("count", len(records)))
	}

	// Initialize fsnotify watcher if real-time watch is enabled
	if s.config.RealTimeWatch {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			s.logger.Warn("failed to create fsnotify watcher, falling back to polling", zap.Error(err))
		} else {
			s.watcher = watcher
			// Add watch paths
			for _, path := range s.config.WatchPaths {
				if err := s.addWatchPath(path); err != nil {
					s.logger.Warn("failed to watch path", zap.String("path", path), zap.Error(err))
				}
			}
			s.logger.Info("fsnotify watcher initialized",
				zap.Int("watch_paths", len(s.config.WatchPaths)))
		}
	}

	s.running = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})
	s.mu.Unlock()

	// Start background worker
	go s.run()

	// Start fsnotify event handler if watcher is active
	if s.watcher != nil {
		go s.handleFSEvents()
	}

	s.logger.Info("filehash service started",
		zap.Strings("watch_paths", s.config.WatchPaths),
		zap.Bool("realtime_watch", s.watcher != nil),
	)

	return nil
}

// Stop gracefully shuts down the service
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()

	// Wait for worker to finish with timeout
	select {
	case <-s.doneCh:
	case <-ctx.Done():
		return ctx.Err()
	}

	// Close watcher
	if s.watcher != nil {
		s.watcher.Close()
	}

	// Close store
	if s.store != nil {
		s.store.Close()
	}

	s.logger.Info("filehash service stopped")
	return nil
}

// Health returns the current health status
func (s *Service) Health() service.HealthStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.config.Enabled {
		return service.HealthStatus{
			Status:    service.HealthHealthy,
			Message:   "disabled",
			LastCheck: time.Now(),
		}
	}

	if !s.running {
		return service.HealthStatus{
			Status:    service.HealthUnhealthy,
			Message:   "not running",
			LastCheck: time.Now(),
		}
	}

	return service.HealthStatus{
		Status:    service.HealthHealthy,
		Message:   "running",
		LastCheck: time.Now(),
		Metrics: map[string]interface{}{
			"files_tracked":    len(s.fileHashes),
			"files_scanned":    s.filesScanned,
			"hashes_computed":  s.hashesComputed,
			"changes_found":    s.changesFound,
			"file_events":      s.fileEvents,
			"realtime_watch":   s.watcher != nil,
			"last_scan":        s.lastScanTime,
			"last_sync":        s.lastSyncTime,
		},
	}
}

// run is the main background worker
func (s *Service) run() {
	defer close(s.doneCh)

	// Initial scan
	s.scanAll()

	scanTicker := time.NewTicker(s.config.ScanInterval)
	syncTicker := time.NewTicker(s.config.SyncInterval)
	defer scanTicker.Stop()
	defer syncTicker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-scanTicker.C:
			s.scanAll()
		case <-syncTicker.C:
			s.syncToAPI()
		case <-s.triggerCh:
			s.scanAll()
		}
	}
}

// scanAll scans all configured watch paths
func (s *Service) scanAll() {
	s.mu.RLock()
	paths := s.config.WatchPaths
	recursive := s.config.Recursive
	maxSize := s.config.MaxFileSize
	s.mu.RUnlock()

	s.logger.Debug("starting file scan", zap.Strings("paths", paths))

	var scanned, computed, changes int64

	for _, watchPath := range paths {
		err := filepath.Walk(watchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				s.logger.Debug("walk error", zap.String("path", path), zap.Error(err))
				return nil // Continue walking
			}

			// Skip directories (unless we need to skip non-recursive)
			if info.IsDir() {
				if !recursive && path != watchPath {
					return filepath.SkipDir
				}
				return nil
			}

			// Skip files that are too large
			if info.Size() > maxSize {
				return nil
			}

			// Skip ignored patterns
			if s.shouldIgnore(path) {
				return nil
			}

			scanned++

			// Check if file changed
			s.mu.RLock()
			existing, exists := s.fileHashes[path]
			s.mu.RUnlock()

			needsHash := !exists ||
				existing.Size != info.Size() ||
				!existing.ModTime.Equal(info.ModTime())

			if needsHash {
				record, err := s.computeFileHash(path, info)
				if err != nil {
					s.logger.Debug("hash error", zap.String("path", path), zap.Error(err))
					return nil
				}

				computed++

				// Check if hash actually changed
				if exists && existing.SHA256 != record.SHA256 {
					changes++
					s.logger.Info("file changed",
						zap.String("path", path),
						zap.String("old_sha256", existing.SHA256[:16]+"..."),
						zap.String("new_sha256", record.SHA256[:16]+"..."),
					)
				}

				s.mu.Lock()
				s.fileHashes[path] = record
				s.mu.Unlock()

				// Save to local store
				if s.store != nil {
					s.store.Save(record)
				}
			}

			return nil
		})

		if err != nil {
			s.logger.Error("scan failed", zap.String("path", watchPath), zap.Error(err))
		}
	}

	s.mu.Lock()
	s.filesScanned += scanned
	s.hashesComputed += computed
	s.changesFound += changes
	s.lastScanTime = time.Now()
	s.mu.Unlock()

	s.logger.Debug("scan complete",
		zap.Int64("scanned", scanned),
		zap.Int64("computed", computed),
		zap.Int64("changes", changes),
	)
}

// computeFileHash computes all hashes for a file
func (s *Service) computeFileHash(path string, info os.FileInfo) (*FileRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	sha256Hash := sha256.New()
	sha1Hash := sha1.New()
	md5Hash := md5.New()

	multiWriter := io.MultiWriter(sha256Hash, sha1Hash, md5Hash)

	buf := make([]byte, 128*1024)
	if _, err := io.CopyBuffer(multiWriter, file, buf); err != nil {
		return nil, err
	}

	now := time.Now()
	return &FileRecord{
		Path:      path,
		Filename:  info.Name(),
		Size:      info.Size(),
		ModTime:   info.ModTime(),
		SHA256:    hex.EncodeToString(sha256Hash.Sum(nil)),
		SHA1:      hex.EncodeToString(sha1Hash.Sum(nil)),
		MD5:       hex.EncodeToString(md5Hash.Sum(nil)),
		FirstSeen: now,
		LastSeen:  now,
		Synced:    false,
	}, nil
}

// syncToAPI syncs unsynced hashes to the filehashes.io API
func (s *Service) syncToAPI() {
	s.mu.RLock()
	endpoint := s.config.APIEndpoint
	apiKey := s.config.APIKey
	s.mu.RUnlock()

	if endpoint == "" {
		return
	}

	// Collect unsynced records
	s.mu.RLock()
	var unsynced []*FileRecord
	for _, r := range s.fileHashes {
		if !r.Synced {
			unsynced = append(unsynced, r)
		}
	}
	s.mu.RUnlock()

	if len(unsynced) == 0 {
		return
	}

	s.logger.Debug("syncing to API", zap.Int("count", len(unsynced)))

	client := NewAPIClient(endpoint, apiKey)
	synced := 0

	for _, record := range unsynced {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := client.SubmitHash(ctx, record)
		cancel()

		if err != nil {
			s.logger.Debug("sync failed", zap.String("path", record.Path), zap.Error(err))
			continue
		}

		// Mark as synced
		s.mu.Lock()
		if r, ok := s.fileHashes[record.Path]; ok {
			r.Synced = true
		}
		s.mu.Unlock()

		if s.store != nil {
			record.Synced = true
			s.store.Save(record)
		}

		synced++
	}

	s.mu.Lock()
	s.lastSyncTime = time.Now()
	s.mu.Unlock()

	if synced > 0 {
		s.logger.Info("synced hashes to API", zap.Int("synced", synced), zap.Int("total", len(unsynced)))
	}
}

// shouldIgnore checks if a path should be ignored
func (s *Service) shouldIgnore(path string) bool {
	s.mu.RLock()
	patterns := s.config.IgnorePatterns
	s.mu.RUnlock()

	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		// Also check against full path for directory patterns
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
	}
	return false
}

// TriggerScan triggers an immediate scan
func (s *Service) TriggerScan() {
	select {
	case s.triggerCh <- struct{}{}:
	default:
	}
}

// GetTrackedFiles returns all tracked files
func (s *Service) GetTrackedFiles() []*FileRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := make([]*FileRecord, 0, len(s.fileHashes))
	for _, r := range s.fileHashes {
		records = append(records, r)
	}
	return records
}

// addWatchPath adds a path to the fsnotify watcher
func (s *Service) addWatchPath(path string) error {
	if s.watcher == nil {
		return nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		// Add directory and optionally subdirectories
		if s.config.Recursive {
			return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
				if err != nil {
					return nil // Skip errors
				}
				if info.IsDir() {
					if err := s.watcher.Add(p); err != nil {
						s.logger.Debug("failed to watch directory", zap.String("path", p), zap.Error(err))
					} else {
						s.logger.Debug("watching directory", zap.String("path", p))
					}
				}
				return nil
			})
		}
		return s.watcher.Add(path)
	}

	// Single file
	return s.watcher.Add(path)
}

// handleFSEvents processes file system events from fsnotify
func (s *Service) handleFSEvents() {
	// Debounce timer to batch rapid file changes
	debounce := make(map[string]time.Time)
	debounceDuration := 500 * time.Millisecond

	for {
		select {
		case <-s.stopCh:
			return

		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}

			// Skip ignored files
			if s.shouldIgnore(event.Name) {
				continue
			}

			// Debounce rapid changes to same file
			if lastTime, exists := debounce[event.Name]; exists {
				if time.Since(lastTime) < debounceDuration {
					continue
				}
			}
			debounce[event.Name] = time.Now()

			s.mu.Lock()
			s.fileEvents++
			s.mu.Unlock()

			// Handle different event types
			switch {
			case event.Op&fsnotify.Create == fsnotify.Create:
				s.handleFileCreate(event.Name)

			case event.Op&fsnotify.Write == fsnotify.Write:
				s.handleFileModify(event.Name)

			case event.Op&fsnotify.Remove == fsnotify.Remove:
				s.handleFileRemove(event.Name)

			case event.Op&fsnotify.Rename == fsnotify.Rename:
				s.handleFileRemove(event.Name)
			}

		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.logger.Warn("fsnotify error", zap.Error(err))
		}
	}
}

// handleFileCreate handles a new file creation
func (s *Service) handleFileCreate(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	// If it's a directory, add it to the watcher
	if info.IsDir() && s.config.Recursive {
		if err := s.watcher.Add(path); err != nil {
			s.logger.Debug("failed to watch new directory", zap.String("path", path), zap.Error(err))
		}
		return
	}

	// Skip files that are too large
	if info.Size() > s.config.MaxFileSize {
		return
	}

	// Compute hash for new file
	record, err := s.computeFileHash(path, info)
	if err != nil {
		s.logger.Debug("failed to hash new file", zap.String("path", path), zap.Error(err))
		return
	}

	s.mu.Lock()
	s.fileHashes[path] = record
	s.hashesComputed++
	s.mu.Unlock()

	// Save to store
	if s.store != nil {
		s.store.Save(record)
	}

	s.logger.Debug("new file detected",
		zap.String("path", path),
		zap.String("sha256", record.SHA256[:16]+"..."))
}

// handleFileModify handles a file modification
func (s *Service) handleFileModify(path string) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}

	// Skip files that are too large
	if info.Size() > s.config.MaxFileSize {
		return
	}

	// Get existing record
	s.mu.RLock()
	existing, exists := s.fileHashes[path]
	s.mu.RUnlock()

	// Compute new hash
	record, err := s.computeFileHash(path, info)
	if err != nil {
		s.logger.Debug("failed to hash modified file", zap.String("path", path), zap.Error(err))
		return
	}

	// Check if hash actually changed
	if exists && existing.SHA256 != record.SHA256 {
		s.mu.Lock()
		s.changesFound++
		s.mu.Unlock()

		s.logger.Info("file modified",
			zap.String("path", path),
			zap.String("old_sha256", existing.SHA256[:16]+"..."),
			zap.String("new_sha256", record.SHA256[:16]+"..."))
	}

	s.mu.Lock()
	s.fileHashes[path] = record
	s.hashesComputed++
	s.mu.Unlock()

	// Save to store
	if s.store != nil {
		s.store.Save(record)
	}
}

// handleFileRemove handles a file removal
func (s *Service) handleFileRemove(path string) {
	s.mu.Lock()
	if _, exists := s.fileHashes[path]; exists {
		delete(s.fileHashes, path)
		s.logger.Debug("file removed", zap.String("path", path))
	}
	s.mu.Unlock()

	// Remove from store
	if s.store != nil {
		s.store.Delete(path)
	}
}
