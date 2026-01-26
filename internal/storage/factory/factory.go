package factory

import (
	"context"
	"fmt"

	"github.com/afterdarksys/afterdark-darkd/internal/storage"
	"github.com/afterdarksys/afterdark-darkd/internal/storage/json"
)

// New creates and initializes a storage backend based on configuration
func New(backend string, config storage.Config) (storage.Store, error) {
	var store storage.Store

	switch backend {
	case "json", "file":
		// Check config path
		if config.Path == "" {
			return nil, fmt.Errorf("storage path is required for json backend")
		}
		jsonStore := json.New()
		if err := jsonStore.Initialize(context.Background(), &config); err != nil {
			return nil, err
		}
		store = jsonStore
	default:
		return nil, fmt.Errorf("unknown storage backend: %s", backend)
	}

	return store, nil
}
