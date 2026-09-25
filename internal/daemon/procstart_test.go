package daemon

import (
	"os"
	"testing"
)

func TestProcessStartRejectsMissingPID(t *testing.T) {
	if !processStart(0).IsZero() || !processStart(-1).IsZero() {
		t.Fatal("invalid pid received a start time")
	}
	started := processStart(os.Getpid())
	if started.IsZero() {
		t.Fatal("current process had no start time")
	}
}
