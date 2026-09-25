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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type EventType int
type Event struct {
	Type          EventType
	Kind          string
	PID           int
	PPID          int
	UID           uint32
	Path          string
	SigningID     string
	Sequence      uint64
	Args          []string
	ArgsTruncated bool
	Start         time.Time
	Responded     bool
}

// Authorizer answers an auth exec. It must not do I/O. False denies.
type Authorizer func(path string, args []string, truncated bool, pid, ppid int, started time.Time) bool

var authorizer struct {
	sync.RWMutex
	fn Authorizer
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

func esKind(kind int) string {
	switch kind {
	case 1:
		return "notify_exec"
	case 2:
		return "notify_fork"
	case 3:
		return "notify_exit"
	case 4:
		return "notify_write"
	case 5:
		return "notify_unlink"
	case 6:
		return "auth_exec"
	default:
		return ""
	}
}

// SetAuthorizer installs the synchronous auth decision. A nil authorizer denies.
func SetAuthorizer(fn Authorizer) {
	authorizer.Lock()
	authorizer.fn = fn
	authorizer.Unlock()
}

//export AuthorizeExec
func AuthorizeExec(path *C.char, args *C.char, truncated C.int, pid C.int, ppid C.int, startSec C.longlong, startUsec C.int) (result C.int) {
	result = 0
	defer func() { recover() }()
	authorizer.RLock()
	fn := authorizer.fn
	authorizer.RUnlock()
	if fn == nil {
		return 0
	}
	var argv []string
	if args != nil {
		joined := C.GoString(args)
		if joined != "" {
			argv = strings.Split(joined, "\x1e")
		}
	}
	var started time.Time
	if startSec > 0 {
		started = time.Unix(int64(startSec), int64(startUsec)*int64(time.Microsecond)).UTC()
	}
	if fn(C.GoString(path), argv, truncated != 0, int(pid), int(ppid), started) {
		return 1
	}
	return 0
}

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
func HandleESFEvent(kind C.int, pid C.int, ppid C.int, uid C.uint, path *C.char, signing *C.char, sequence C.ulonglong, observed C.int, responded C.int, truncated C.int, startSec C.longlong, startUsec C.int, args *C.char) {
	var argv []string
	if args != nil {
		joined := C.GoString(args)
		if joined != "" {
			argv = strings.Split(joined, "\x1e")
		}
	}
	var started time.Time
	if startSec > 0 {
		started = time.Unix(int64(startSec), int64(startUsec)*int64(time.Microsecond)).UTC()
	}
	e := Event{Type: EventType(kind), Kind: esKind(int(observed)), PID: int(pid), PPID: int(ppid), UID: uint32(uid), Path: C.GoString(path), SigningID: C.GoString(signing), Sequence: uint64(sequence), Args: argv, ArgsTruncated: truncated != 0, Start: started, Responded: responded != 0}
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
