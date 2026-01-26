//go:build darwin && !esf

// Package esf provides a stub implementation when ESF framework is not available.
// Build with -tags esf to enable full EndpointSecurity support.
package esf

import "errors"

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
	Type EventType
	PID  int
	Path string
}
