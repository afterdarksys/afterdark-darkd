//go:build darwin && !cgo

package memscan

import (
	"fmt"
	"github.com/afterdarksys/afterdark-darkd/internal/models"
)

func darwinRead(int, uint64, uint64) ([]byte, error) {
	return nil, fmt.Errorf("Mach memory access requires a CGO-enabled build")
}
func darwinRegions(int) ([]models.MemoryRegion, error) {
	return nil, fmt.Errorf("Mach memory access requires a CGO-enabled build")
}
