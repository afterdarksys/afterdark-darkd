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
	// Answer is the auth result sent to the kernel ("allow" or "deny");
	// empty for notify events. Fallback marks an answer made by the C
	// basename rule because the Go decision was unavailable.
	Answer    string
	Fallback  bool
	TargetPID int
	Signal    int
}

// Authorizer answers an auth exec. It must not do I/O. False denies.
type Authorizer func(path string, args []string, truncated bool, pid, ppid int, started time.Time) bool

// SignalAuthorizer answers an auth signal aimed at this process. It must not
// do I/O. False denies.
type SignalAuthorizer func(sender, target, sig int) bool

var authorizer struct {
	sync.RWMutex
	fn     Authorizer
	signal SignalAuthorizer
}

// Client owns two ES clients: auth (exec, signal) and notify. The auth client
// is optional; authErr says why it is not enforcing.
type Client struct {
	stop    chan struct{}
	done    chan struct{}
	running bool
	once    sync.Once
	auth    bool
	authErr error
	muteErr error
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
	case 7:
		return "auth_signal"
	default:
		return ""
	}
}

// SetAuthorizer installs the synchronous exec decision. With none installed
// the C fallback answers: allow unless the executable is a stop tool.
func SetAuthorizer(fn Authorizer) {
	authorizer.Lock()
	authorizer.fn = fn
	authorizer.Unlock()
}

// SetSignalAuthorizer installs the synchronous signal decision. With none
// installed the signal is allowed.
func SetSignalAuthorizer(fn SignalAuthorizer) {
	authorizer.Lock()
	authorizer.signal = fn
	authorizer.Unlock()
}

// internalError is returned across cgo when no decision was made (panic or no
// authorizer). C then applies its fallback.
const internalError = -1

//export AuthorizeSignal
func AuthorizeSignal(sender C.int, target C.int, sig C.int) (result C.int) {
	result = internalError
	defer func() { recover() }()
	authorizer.RLock()
	fn := authorizer.signal
	authorizer.RUnlock()
	if fn == nil {
		return internalError
	}
	if fn(int(sender), int(target), int(sig)) {
		return 1
	}
	return 0
}

//export AuthorizeExec
func AuthorizeExec(path *C.char, args *C.char, truncated C.int, pid C.int, ppid C.int, startSec C.longlong, startUsec C.int) (result C.int) {
	result = internalError
	defer func() { recover() }()
	authorizer.RLock()
	fn := authorizer.fn
	authorizer.RUnlock()
	if fn == nil || path == nil {
		return internalError
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
	if code := C.init_notify_client(); code != 0 {
		lifecycle.Unlock()
		return nil, fmt.Errorf("Endpoint Security initialization failed: code %d (verify entitlement and Full Disk Access)", int(code))
	}
	c := &Client{}
	if code := C.mute_self_notify(); code != 0 {
		c.muteErr = fmt.Errorf("Endpoint Security could not mute this process on the notify client: code %d", int(code))
	}
	if code := C.init_auth_client(); code != 0 {
		c.authErr = fmt.Errorf("Endpoint Security auth client initialization failed: code %d", int(code))
	} else {
		c.auth = true
	}
	return c, nil
}

// Subscribe fails only when notify monitoring cannot start. An auth
// subscription failure is kept in AuthError.
func (c *Client) Subscribe() error {
	if code := C.subscribe_notify(); code != 0 {
		return fmt.Errorf("Endpoint Security subscription failed: %d", int(code))
	}
	if c.auth {
		if code := C.subscribe_auth(); code != 0 {
			c.auth = false
			c.authErr = fmt.Errorf("Endpoint Security auth subscription failed: %d", int(code))
		}
	}
	return nil
}

// AuthError is nil only when exec and signal authorization are subscribed.
func (c *Client) AuthError() error {
	if c.auth {
		return nil
	}
	if c.authErr == nil {
		return fmt.Errorf("Endpoint Security auth client is not subscribed")
	}
	return c.authErr
}

// MuteError reports a failure to mute this process on the notify client.
func (c *Client) MuteError() error { return c.muteErr }

//export HandleESFEvent
func HandleESFEvent(kind C.int, pid C.int, ppid C.int, uid C.uint, path *C.char, signing *C.char, sequence C.ulonglong, observed C.int, responded C.int, answer C.int, fallback C.int, targetPID C.int, sig C.int, truncated C.int, startSec C.longlong, startUsec C.int, args *C.char) {
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
	e := Event{Type: EventType(kind), Kind: esKind(int(observed)), PID: int(pid), PPID: int(ppid), UID: uint32(uid), Path: C.GoString(path), SigningID: C.GoString(signing), Sequence: uint64(sequence), Args: argv, ArgsTruncated: truncated != 0, Start: started, Responded: responded != 0,
		Fallback: fallback != 0, TargetPID: int(targetPID), Signal: int(sig)}
	if e.Kind == "auth_exec" || e.Kind == "auth_signal" {
		e.Answer = "deny"
		if answer == 1 {
			e.Answer = "allow"
		}
	}
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
		C.stop_es_clients()
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
