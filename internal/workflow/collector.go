package workflow

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type cappedBuffer struct {
	data     []byte
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := MaxReport - len(b.data)
	if len(p) > remaining {
		b.exceeded = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil
}

// Collect executes only known companions alongside this executable, never a
// shell or a PATH-resolved command. Installation permissions establish trust.
func Collect(ctx context.Context, tool string) ([]byte, error) {
	allowed := false
	for _, s := range Catalog()[0].Steps {
		if s.Tool == tool {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("unknown collector")
	}
	if runtime.GOOS != "darwin" {
		return nil, errors.New("live baseline collection requires macOS")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return nil, err
	}
	binary := filepath.Join(filepath.Dir(executable), tool)
	info, err := os.Lstat(binary)
	if err != nil {
		return nil, fmt.Errorf("collector unavailable: %s", tool)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("collector must be a regular file without group/world write access")
	}
	cmd := exec.CommandContext(ctx, binary, "scan", "--json")
	cmd.WaitDelay = time.Second
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return nil, errors.New("collector output exceeded limit")
	}
	if ctx.Err() != nil {
		return stdout.data, ctx.Err()
	}
	if err != nil {
		return stdout.data, fmt.Errorf("collector %s failed: %w", tool, err)
	}
	return stdout.data, nil
}
