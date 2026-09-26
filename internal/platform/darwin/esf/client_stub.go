//go:build darwin && (!esf || !cgo)

// Package esf provides a stub implementation when ESF framework is not available.
// Build with -tags esf to enable full EndpointSecurity support.
package esf

import (
	"errors"
	"time"
)

// Client is a stub when ESF is not available
type Client struct{}

// NewClient returns an error when ESF framework is not available
func NewClient() (*Client, error) {
	return nil, errors.New("EndpointSecurity framework not available - build with -tags esf")
}

// Subscribe is a stub
func (c *Client) Subscribe() error {
	return errors.New("EndpointSecurity not available")
}

// Start is a stub
func (c *Client) Start(handler func(Event)) {}

// Stop is a stub
func (c *Client) Stop() {}

// GlobalHandler stub
var GlobalHandler func(Event)

// EventType for stub
type EventType int

// Event for stub
type Event struct {
	Type          EventType
	Kind          string
	PID           int
	PPID          int
	UID           uint32
	SigningID     string
	Sequence      uint64
	Path          string
	Args          []string
	ArgsTruncated bool
	Start         time.Time
	Responded     bool
	Answer        string
	Fallback      bool
	TargetPID     int
	Signal        int
}

// SetAuthorizer is a no-op when the Endpoint Security bridge is not built.
func SetAuthorizer(func(string, []string, bool, int, int, time.Time) bool) {}

// SetSignalAuthorizer is a no-op when the Endpoint Security bridge is not built.
func SetSignalAuthorizer(func(int, int, int) bool) {}

// AuthError reports that nothing is enforced without the bridge.
func (c *Client) AuthError() error { return errors.New("EndpointSecurity not available") }

// MuteError is a stub.
func (c *Client) MuteError() error { return nil }

func DroppedEvents() uint64 { return 0 }
