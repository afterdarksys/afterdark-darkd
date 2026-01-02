package storage

import (
	"context"
	"errors"
)

var (
	ErrNotFound     = errors.New("key not found")
	ErrKeyExists    = errors.New("key already exists")
	ErrInvalidKey   = errors.New("invalid key")
	ErrStorageFull  = errors.New("storage is full")
)

// Store defines the interface for data persistence
type Store interface {
	// Initialize the storage backend
	Initialize(ctx context.Context, config *Config) error

	// Close the storage backend
	Close() error

	// Save stores data with the given key
	Save(ctx context.Context, collection, key string, data interface{}) error

	// Load retrieves data for the given key
	Load(ctx context.Context, collection, key string, dest interface{}) error

	// Delete removes data for the given key
	Delete(ctx context.Context, collection, key string) error

	// List returns all keys in a collection
	List(ctx context.Context, collection string) ([]string, error)

	// Query performs a structured query
	Query(ctx context.Context, q *Query) ([]map[string]interface{}, error)

	// Stats returns storage statistics
	Stats() *Stats
}

// Config holds storage configuration
type Config struct {
	Path            string `yaml:"path" json:"path"`
	BackupEnabled   bool   `yaml:"backup_enabled" json:"backup_enabled"`
	BackupRetention int    `yaml:"backup_retention" json:"backup_retention"` // days
	CompactInterval int    `yaml:"compact_interval" json:"compact_interval"` // hours
}

// Query represents a structured query
type Query struct {
	Collection string                 `json:"collection"`
	Filter     map[string]interface{} `json:"filter,omitempty"`
	Sort       []SortField            `json:"sort,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Offset     int                    `json:"offset,omitempty"`
}

// SortField represents a sort specification
type SortField struct {
	Field string `json:"field"`
	Desc  bool   `json:"desc"`
}

// Stats contains storage statistics
type Stats struct {
	Collections   int   `json:"collections"`
	TotalKeys     int   `json:"total_keys"`
	TotalSizeKB   int64 `json:"total_size_kb"`
	LastBackup    int64 `json:"last_backup,omitempty"` // unix timestamp
	BackupSizeKB  int64 `json:"backup_size_kb,omitempty"`
}
