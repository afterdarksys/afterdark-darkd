package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const (
	// NonceFileName is created in the daemon storage directory.
	NonceFileName = "control-nonces.json"

	maxNonceEntries   = 4096
	maxNonceFileBytes = 1 << 20
)

var (
	ErrReplay         = errors.New("control token nonce was already used")
	ErrNonceStoreFull = errors.New("control nonce store is full")
	nonceHashPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type nonceFile struct {
	Version int              `json:"version"`
	Nonces  map[string]int64 `json:"nonces"`
}

// NonceStore durably records used nonce hashes with their token's not_after.
// Entries whose not_after has passed are pruned: such a token is rejected as
// expired anyway. A store that cannot be read or written denies every token.
type NonceStore struct {
	mu   sync.Mutex
	path string
}

func NewNonceStore(path string) *NonceStore { return &NonceStore{path: path} }

// Consume records hash, or returns ErrReplay if it is already present. The
// record is on disk before Consume returns nil.
func (s *NonceStore) Consume(hash string, notAfter, now time.Time) error {
	if !nonceHashPattern.MatchString(hash) {
		return errors.New("invalid nonce hash")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.load()
	if err != nil {
		return err
	}
	for h, exp := range entries {
		if exp < now.Unix() {
			delete(entries, h)
		}
	}
	if _, used := entries[hash]; used {
		return ErrReplay
	}
	if len(entries) >= maxNonceEntries {
		return ErrNonceStoreFull
	}
	entries[hash] = notAfter.Unix()
	return s.save(entries)
}

func (s *NonceStore) load() (map[string]int64, error) {
	if s.path == "" {
		return nil, errors.New("control nonce store path is not configured")
	}
	f, err := openNoFollow(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]int64{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open control nonce store: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat control nonce store: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("control nonce store %s must be a regular 0600 file", s.path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxNonceFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read control nonce store: %w", err)
	}
	if len(data) > maxNonceFileBytes {
		return nil, errors.New("control nonce store exceeds size limit")
	}
	var file nonceFile
	if err := json.Unmarshal(data, &file); err != nil || file.Version != 1 {
		return nil, errors.New("control nonce store is corrupt")
	}
	if len(file.Nonces) > maxNonceEntries {
		return nil, errors.New("control nonce store holds too many entries")
	}
	for h := range file.Nonces {
		if !nonceHashPattern.MatchString(h) {
			return nil, errors.New("control nonce store is corrupt")
		}
	}
	if file.Nonces == nil {
		file.Nonces = map[string]int64{}
	}
	return file.Nonces, nil
}

func (s *NonceStore) save(entries map[string]int64) error {
	data, err := json.Marshal(nonceFile{Version: 1, Nonces: entries})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create control nonce directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".control-nonces-*")
	if err != nil {
		return fmt.Errorf("write control nonce store: %w", err)
	}
	name := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("commit control nonce store: %w", err)
	}
	committed = true
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync control nonce directory: %w", err)
	}
	syncErr := d.Sync()
	closeErr := d.Close()
	if syncErr != nil {
		return fmt.Errorf("sync control nonce directory: %w", syncErr)
	}
	return closeErr
}
