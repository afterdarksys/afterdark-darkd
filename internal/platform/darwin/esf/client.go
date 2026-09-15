//go:build darwin && esf && cgo

package esf

/*
#cgo CFLAGS: -x objective-c -fblocks
#cgo LDFLAGS: -lEndpointSecurity -framework Foundation -lbsm
#include "client.h"
*/
import "C"
import (
	"fmt"
	"sync"
	"sync/atomic"
)

type EventType int
type Event struct {
	Type      EventType
	PID       int
	PPID      int
	UID       uint32
	Path      string
	SigningID string
	Sequence  uint64
}
type Client struct {
	stop    chan struct{}
	done    chan struct{}
	running bool
	once    sync.Once
}

var callbacks struct {
	sync.RWMutex
	queue chan Event
}
var lifecycle sync.Mutex
var dropped atomic.Uint64

func DroppedEvents() uint64 { return dropped.Load() }
func NewClient() (*Client, error) {
	if !lifecycle.TryLock() {
		return nil, fmt.Errorf("Endpoint Security client already exists")
	}
	if code := C.init_es_client(); code != 0 {
		lifecycle.Unlock()
		return nil, fmt.Errorf("Endpoint Security initialization failed: code %d (verify entitlement and Full Disk Access)", int(code))
	}
	return &Client{}, nil
}
func (c *Client) Subscribe() error {
	if code := C.subscribe_to_events(); code != 0 {
		return fmt.Errorf("Endpoint Security subscription failed: %d", int(code))
	}
	return nil
}

//export HandleESFEvent
func HandleESFEvent(kind C.int, pid C.int, ppid C.int, uid C.uint, path *C.char, signing *C.char, sequence C.ulonglong) {
	e := Event{Type: EventType(kind), PID: int(pid), PPID: int(ppid), UID: uint32(uid), Path: C.GoString(path), SigningID: C.GoString(signing), Sequence: uint64(sequence)}
	callbacks.RLock()
	defer callbacks.RUnlock()
	if callbacks.queue == nil {
		dropped.Add(1)
		return
	}
	select {
	case callbacks.queue <- e:
	default:
		dropped.Add(1)
	}
}
func (c *Client) Start(handler func(Event)) {
	q := make(chan Event, 1024)
	c.stop = make(chan struct{})
	c.done = make(chan struct{})
	c.running = true
	callbacks.Lock()
	callbacks.queue = q
	callbacks.Unlock()
	go func() {
		defer close(c.done)
		for {
			select {
			case <-c.stop:
				return
			case e := <-q:
				handler(e)
			}
		}
	}()
}
func (c *Client) Stop() {
	c.once.Do(func() {
		C.stop_es_client()
		callbacks.Lock()
		callbacks.queue = nil
		callbacks.Unlock()
		if c.running {
			close(c.stop)
			<-c.done
			c.running = false
		}
		lifecycle.Unlock()
	})
}
