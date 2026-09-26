package control

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

// MaintenanceWindow is how long a verified token lets darkd be stopped.
const MaintenanceWindow = 120 * time.Second

// Window is a deadline on a monotonic clock. Open is lock-free and cheap
// because the Endpoint Security callbacks read it on every auth event.
type Window struct {
	deadline atomic.Int64
	mono     func() time.Duration
}

// NewWindow returns a closed window on the process monotonic clock.
func NewWindow() *Window {
	start := time.Now()
	return newWindow(func() time.Duration { return time.Since(start) })
}

func newWindow(mono func() time.Duration) *Window {
	w := &Window{mono: mono}
	// Closed until OpenFor: the clock starts at zero and deadline is -1.
	w.deadline.Store(-1)
	return w
}

// OpenFor opens the window for d from now. It never shortens an open window.
func (w *Window) OpenFor(d time.Duration) {
	next := int64(w.mono() + d)
	for {
		current := w.deadline.Load()
		if current >= next || w.deadline.CompareAndSwap(current, next) {
			return
		}
	}
}

// Open reports whether a verified token opened the window and it has not
// yet elapsed. A nil window is closed.
func (w *Window) Open() bool {
	if w == nil {
		return false
	}
	return int64(w.mono()) < w.deadline.Load()
}

// Grant describes an accepted token. It never carries the token or nonce.
type Grant struct {
	Action         string
	SystemID       string
	KeyFingerprint string
	NonceHash      string
	IssuedAt       time.Time
	NotAfter       time.Time
	Window         time.Duration
}

// Config wires a Controller.
type Config struct {
	// KeysFile holds the trusted Ed25519 public keys.
	KeysFile string
	// KeysOwner is the uid that must own KeysFile and its directory (root).
	KeysOwner uint32
	// NonceFile persists used nonces across restarts.
	NonceFile string
	// SystemID returns this endpoint's identity.
	SystemID func() (string, error)
	// Window is opened on success; required.
	Window *Window
	// Now is the wall clock used for token validity; nil means time.Now.
	Now func() time.Time
}

// Controller verifies stop tokens and opens the maintenance window.
type Controller struct {
	cfg    Config
	nonces *NonceStore
}

func New(cfg Config) (*Controller, error) {
	if cfg.Window == nil {
		return nil, errors.New("control window is required")
	}
	if cfg.SystemID == nil {
		return nil, errors.New("control system id source is required")
	}
	if cfg.NonceFile == "" {
		return nil, errors.New("control nonce file is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Controller{cfg: cfg, nonces: NewNonceStore(cfg.NonceFile)}, nil
}

// Window exposes the maintenance window for the Endpoint Security authorizer.
func (c *Controller) Window() *Window { return c.cfg.Window }

// Authorize verifies raw, consumes its nonce, runs audit, and only then opens
// the window. Any failure leaves the window as it was and returns an error.
// A nonce is consumed before audit so an audit failure cannot be retried with
// the same token.
func (c *Controller) Authorize(raw []byte, audit func(Grant) error) (Grant, error) {
	if audit == nil {
		return Grant{}, errors.New("control audit sink is required")
	}
	if len(raw) > MaxTokenSize {
		return Grant{}, ErrTokenTooLarge
	}
	keys, err := LoadPublicKeys(c.cfg.KeysFile, c.cfg.KeysOwner)
	if err != nil {
		return Grant{}, err
	}
	systemID, err := c.cfg.SystemID()
	if err != nil {
		return Grant{}, fmt.Errorf("endpoint identity unavailable: %w", err)
	}
	now := c.cfg.Now()
	v, err := verifyToken(raw, keys, systemID, now)
	if err != nil {
		return Grant{}, err
	}
	if err := c.nonces.Consume(v.NonceHash, time.Unix(v.Claims.NotAfter, 0), now); err != nil {
		return Grant{}, err
	}
	grant := Grant{
		Action:         v.Claims.Action,
		SystemID:       v.Claims.SystemID,
		KeyFingerprint: Fingerprint(v.Key),
		NonceHash:      v.NonceHash,
		IssuedAt:       time.Unix(v.Claims.IssuedAt, 0).UTC(),
		NotAfter:       time.Unix(v.Claims.NotAfter, 0).UTC(),
		Window:         MaintenanceWindow,
	}
	if err := audit(grant); err != nil {
		return Grant{}, fmt.Errorf("control event could not be journaled; window not opened: %w", err)
	}
	c.cfg.Window.OpenFor(MaintenanceWindow)
	return grant, nil
}
