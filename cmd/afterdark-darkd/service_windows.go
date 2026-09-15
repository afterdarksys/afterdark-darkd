//go:build windows

package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/svc"
	svcdebug "golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

// runService handles Windows service execution
func runService(cmd *cobra.Command, args []string) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	// If not running as a service, run normally
	if !isService {
		return runDaemon(cmd, args)
	}

	// Running as a service
	return runWindowsService()
}

func runWindowsService() error {
	const svcName = "afterdark-darkd"

	// Setup event log
	elog, err := eventlog.Open(svcName)
	if err != nil {
		return err
	}
	defer elog.Close()

	elog.Info(1, "Starting "+svcName+" service")

	run := svc.Run
	if debugService {
		run = svcdebug.Run
	}

	err = run(svcName, &afterdarkService{elog: elog})
	if err != nil {
		elog.Error(1, "Service failed: "+err.Error())
		return err
	}

	elog.Info(1, "Service stopped")
	return nil
}

var debugService = false

type afterdarkService struct {
	elog svcdebug.Log
}

func (m *afterdarkService) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	s <- svc.Status{State: svc.StartPending, WaitHint: 60000}

	// Create context for the daemon
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start daemon in a goroutine
	errCh := make(chan error, 1)
	ready := make(chan struct{})
	go func() {
		errCh <- runDaemonWithReady(ctx, func() { close(ready) })
	}()

	// Wait for daemon readiness before telling SCM the service is running.
	select {
	case <-ready:
	case err := <-errCh:
		if err != nil {
			m.elog.Error(1, err.Error())
		}
		return false, 1
	}
	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				m.elog.Info(1, "Service stopping")
				s <- svc.Status{State: svc.StopPending, WaitHint: 35000}
				cancel()
				timer := time.NewTimer(35 * time.Second)
				defer timer.Stop()
				select {
				case err := <-errCh:
					if err != nil {
						return false, 1
					}
				case <-timer.C:
					return false, 1
				}
				break loop
			case svc.ParamChange:
				m.elog.Warning(1, "Live configuration reload is unsupported; restart the service")
			default:
				m.elog.Error(1, "Unexpected control request")
			}
		case err := <-errCh:
			if err != nil {
				m.elog.Error(1, "Daemon error: "+err.Error())
				return false, 1 // Error exit code
			}
			break loop
		}
	}

	return false, 0
}
