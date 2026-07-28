//go:build !darwin && !linux

package peercred

func CurrentUID() uint32 { return 0 }
