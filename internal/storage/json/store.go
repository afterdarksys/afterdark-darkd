package json

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/afterdarksys/afterdark-darkd/internal/storage"
)

// Store implements a JSON file-based storage backend
type Store struct {
	config  *storage.Config
	basePath string
	mu       sync.RWMutex
	cache    map[string]map[string]interface{} // collection -> key -> data
}

// New creates a new JSON store
func New() *Store {
	return &Store{
		cache: make(map[string]map[string]interface{}),
	}
}

// Initialize sets up the JSON store
func (s *Store) Initialize(ctx context.Context, config *storage.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.config = config
	s.basePath = config.Path

	// Create base directory
	if err := os.MkdirAll(s.basePath, 0700); err != nil {
		return fmt.Errorf("failed to create storage directory: %w", err)
	}

	// Load existing data into cache
	return s.loadCache()
}

func (s *Store) loadCache() error {
	entries, err := os.ReadDir(s.basePath)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			collection := entry.Name()
			s.cache[collection] = make(map[string]interface{})

			collPath := filepath.Join(s.basePath, collection)
			files, err := os.ReadDir(collPath)
			if err != nil {
				continue
			}

			for _, file := range files {
				if filepath.Ext(file.Name()) != ".json" {
					continue
				}
				key := file.Name()[:len(file.Name())-5] // remove .json

				data, err := os.ReadFile(filepath.Join(collPath, file.Name()))
				if err != nil {
					continue
				}

				var value interface{}
				if err := json.Unmarshal(data, &value); err != nil {
					continue
				}
				s.cache[collection][key] = value
			}
		}
	}
	return nil
}

// Close closes the store
func (s *Store) Close() error {
	return nil
}

// Save stores data with the given key
func (s *Store) Save(ctx context.Context, collection, key string, data interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure collection directory exists
	collPath := filepath.Join(s.basePath, collection)
	if err := os.MkdirAll(collPath, 0700); err != nil {
		return fmt.Errorf("failed to create collection directory: %w", err)
	}

	// Marshal data
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Write to file atomically
	filePath := filepath.Join(collPath, key+".json")
	tmpPath := filePath + ".tmp"

	if err := os.WriteFile(tmpPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename file: %w", err)
	}

	// Update cache
	if s.cache[collection] == nil {
		s.cache[collection] = make(map[string]interface{})
	}
	s.cache[collection][key] = data

	return nil
}

// Load retrieves data for the given key
func (s *Store) Load(ctx context.Context, collection, key string, dest interface{}) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check cache first
	if coll, ok := s.cache[collection]; ok {
		if data, ok := coll[key]; ok {
			// Re-marshal and unmarshal to copy to dest
			jsonData, err := json.Marshal(data)
			if err != nil {
				return err
			}
			return json.Unmarshal(jsonData, dest)
		}
	}

	return storage.ErrNotFound
}

// Delete removes data for the given key
func (s *Store) Delete(ctx context.Context, collection, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := filepath.Join(s.basePath, collection, key+".json")
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	// Update cache
	if coll, ok := s.cache[collection]; ok {
		delete(coll, key)
	}

	return nil
}

// List returns all keys in a collection
func (s *Store) List(ctx context.Context, collection string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if coll, ok := s.cache[collection]; ok {
		keys := make([]string, 0, len(coll))
		for key := range coll {
			keys = append(keys, key)
		}
		return keys, nil
	}

	return []string{}, nil
}

// Query performs a structured query
func (s *Store) Query(ctx context.Context, q *storage.Query) ([]map[string]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]map[string]interface{}, 0)

	coll, ok := s.cache[q.Collection]
	if !ok {
		return results, nil
	}

	for _, data := range coll {
		if m, ok := data.(map[string]interface{}); ok {
			if s.matchFilter(m, q.Filter) {
				results = append(results, m)
			}
		}
	}

	// Apply limit and offset
	if q.Offset > 0 && q.Offset < len(results) {
		results = results[q.Offset:]
	}
	if q.Limit > 0 && q.Limit < len(results) {
		results = results[:q.Limit]
	}

	return results, nil
}

func (s *Store) matchFilter(data, filter map[string]interface{}) bool {
	if filter == nil {
		return true
	}
	for k, v := range filter {
		if data[k] != v {
			return false
		}
	}
	return true
}

// Stats returns storage statistics
func (s *Store) Stats() *storage.Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &storage.Stats{
		Collections: len(s.cache),
	}

	for _, coll := range s.cache {
		stats.TotalKeys += len(coll)
	}

	// Calculate total size
	filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			stats.TotalSizeKB += info.Size() / 1024
		}
		return nil
	})

	return stats
}

// Backup creates a backup of the storage
func (s *Store) Backup(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	backupDir := filepath.Join(s.basePath, ".backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("backup-%s.json", timestamp))

	data, err := json.MarshalIndent(s.cache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(backupPath, data, 0600)
}
