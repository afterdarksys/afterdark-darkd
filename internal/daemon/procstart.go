package daemon

import (
	"time"

	gopsutilprocess "github.com/shirou/gopsutil/v3/process"
)

// processStart returns the creation time of pid. A miss stays zero so the
// DNS event remains partial instead of inventing an identity.
func processStart(pid int) time.Time {
	if pid <= 0 {
		return time.Time{}
	}
	proc, err := gopsutilprocess.NewProcess(int32(pid))
	if err != nil {
		return time.Time{}
	}
	ms, err := proc.CreateTime()
	if err != nil || ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}
