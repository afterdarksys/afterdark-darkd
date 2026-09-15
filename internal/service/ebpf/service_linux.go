//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/events"
	"github.com/afterdarksys/afterdark-darkd/internal/service"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const ServiceName = "ebpf_monitor"

type Config struct {
	Enabled bool `mapstructure:"enabled"`
}
type Service struct {
	mu       sync.Mutex
	registry service.RegistryInterface
	program  *ebpf.Program
	output   *ebpf.Map
	probe    link.Link
	reader   *perf.Reader
	done     chan struct{}
	lastErr  error
	lost     atomic.Uint64
}

func New(_ *Config, r service.RegistryInterface) (*Service, error) { return &Service{registry: r}, nil }
func (s *Service) Name() string                                    { return ServiceName }
func (s *Service) Configure(interface{}) error {
	return fmt.Errorf("eBPF configuration requires restart")
}
func (s *Service) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reader != nil {
		return nil
	}
	err := s.attach()
	s.lastErr = err
	if err != nil {
		s.cleanup()
		return nil
	}
	s.done = make(chan struct{})
	go s.consume()
	return nil
}
func (s *Service) attach() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	var err error
	s.output, err = ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerfEventArray, KeySize: 4, ValueSize: 4, MaxEntries: uint32(runtime.NumCPU())})
	if err != nil {
		return err
	}
	// Helpers provide stable PID/UID/comm data without kernel struct offsets.
	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1), asm.FnGetCurrentPidTgid.Call(), asm.RSh.Imm(asm.R0, 32), asm.StoreMem(asm.RFP, -32, asm.R0, asm.Word),
		asm.FnGetCurrentUidGid.Call(), asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.StoreImm(asm.RFP, -24, 0, asm.DWord), asm.StoreImm(asm.RFP, -16, 0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP), asm.Add.Imm(asm.R1, -24), asm.Mov.Imm(asm.R2, 16), asm.FnGetCurrentComm.Call(),
		asm.FnKtimeGetNs.Call(), asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R6), asm.LoadMapPtr(asm.R2, s.output.FD()), asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		asm.Mov.Reg(asm.R4, asm.RFP), asm.Add.Imm(asm.R4, -32), asm.Mov.Imm(asm.R5, 32), asm.FnPerfEventOutput.Call(), asm.Mov.Imm(asm.R0, 0), asm.Return()}
	s.program, err = ebpf.NewProgram(&ebpf.ProgramSpec{Name: "darkd_exec", Type: ebpf.TracePoint, License: "GPL", Instructions: instructions})
	if err != nil {
		return err
	}
	s.reader, err = perf.NewReader(s.output, os.Getpagesize()*8)
	if err != nil {
		return err
	}
	s.probe, err = link.Tracepoint("sched", "sched_process_exec", s.program, nil)
	return err
}
func (s *Service) consume() {
	defer close(s.done)
	for {
		r, err := s.reader.Read()
		if err != nil {
			if !errors.Is(err, perf.ErrClosed) {
				s.mu.Lock()
				s.lastErr = err
				s.mu.Unlock()
			}
			return
		}
		if r.LostSamples > 0 {
			s.lost.Add(r.LostSamples)
			continue
		}
		if len(r.RawSample) < 32 {
			s.lost.Add(1)
			continue
		}
		d := r.RawSample
		event := map[string]interface{}{"pid": binary.NativeEndian.Uint32(d[:4]), "uid": binary.NativeEndian.Uint32(d[4:8]), "comm": strings.TrimRight(string(d[8:24]), "\x00"), "monotonic_ns": binary.NativeEndian.Uint64(d[24:32])}
		if err := events.Emit(s.registry, ServiceName, "process.exec", "info", event); err != nil {
			s.lost.Add(1)
		}
	}
}
func (s *Service) cleanup() {
	if s.probe != nil {
		s.probe.Close()
		s.probe = nil
	}
	if s.reader != nil {
		s.reader.Close()
		s.reader = nil
	}
	if s.program != nil {
		s.program.Close()
		s.program = nil
	}
	if s.output != nil {
		s.output.Close()
		s.output = nil
	}
}
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	reader, done := s.reader, s.done
	if reader != nil {
		reader.Close()
	}
	s.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanup()
	s.done = nil
	return nil
}
func (s *Service) Health() service.HealthStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := service.HealthStatus{Status: service.HealthHealthy, Message: "sched_process_exec tracepoint attached", LastCheck: time.Now(), Metrics: map[string]interface{}{"lost_events": s.lost.Load()}}
	if s.lastErr != nil {
		h.Status = service.HealthDegraded
		h.Message = s.lastErr.Error()
	} else if s.reader == nil {
		h.Status = service.HealthUnhealthy
		h.Message = "eBPF stopped"
	} else if s.lost.Load() > 0 {
		h.Status = service.HealthDegraded
		h.Message = "eBPF event loss observed"
	}
	return h
}
