//go:build darwin && cgo

package memscan

import (
	"bytes"
	"go.uber.org/zap"
	"os"
	"runtime"
	"testing"
	"unsafe"
)

func TestMachSelfRead(t *testing.T) {
	data := []byte("AfterDark memory evidence fixture")
	got, err := darwinRead(os.Getpid(), uint64(uintptr(unsafe.Pointer(&data[0]))), uint64(len(data)))
	runtime.KeepAlive(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("memory content mismatch")
	}
	regions, err := darwinRegions(os.Getpid())
	if err != nil || len(regions) == 0 {
		t.Fatalf("regions=%d error=%v", len(regions), err)
	}
	reader, _ := NewDarwinReader(zap.NewNop())
	info, err := reader.GetProcessInfo(os.Getpid())
	if err != nil || info.Name == "" {
		t.Fatalf("process evidence: %v %v", info, err)
	}
	if _, err := darwinRead(os.Getpid(), 0, 65<<20); err == nil {
		t.Fatal("oversized read accepted")
	}
}
