//go:build darwin && esf

package esf

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework EndpointSecurity -framework Foundation

#include <stdlib.h>
#include "client.h"
*/
import "C"
import (
	"errors"
	"fmt"
)

// Client wraps the C EndpointSecurity client
type Client struct {
	running bool
}

// NewClient creates a new ESF client
func NewClient() (*Client, error) {
	if res := C.init_es_client(); res != 0 {
		return nil, errors.New("failed to initialize ES client (root/entitlements required)")
	}
	return &Client{}, nil
}

// Subscribe subscribes to core events
func (c *Client) Subscribe() error {
	if res := C.subscribe_to_events(); res != 0 {
		return fmt.Errorf("failed to subscribe to events")
	}
	return nil
}

//export HandleESFEvent
func HandleESFEvent(evtType C.int, pid C.int, path *C.char) {
	goPath := C.GoString(path)
	// Dispatch to Global Handler (simplest for CGO)
	if GlobalHandler != nil {
		GlobalHandler(Event{
			Type: EventType(evtType),
			PID:  int(pid),
			Path: goPath,
		})
	}
}

// GlobalHandler is a singleton for CGO callbacks
var GlobalHandler func(Event)

type EventType int

type Event struct {
	Type EventType
	PID  int
	Path string
}

// Start begins processing events
func (c *Client) Start(handler func(Event)) {
	GlobalHandler = handler
	C.start_handling_events()
	c.running = true
}

// Stop stops the client
func (c *Client) Stop() {
	if c.running {
		C.stop_es_client()
		c.running = false
		GlobalHandler = nil
	}
}
