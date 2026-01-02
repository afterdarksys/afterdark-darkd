//go:build !darwin && !linux && !windows

package platform

// NewMacOS creates a new macOS platform (stub for unsupported builds)
func NewMacOS() (Platform, error) {
	return nil, &ErrUnsupportedPlatform{OS: "unsupported"}
}

// NewWindows creates a new Windows platform (stub for unsupported builds)
func NewWindows() (Platform, error) {
	return nil, &ErrUnsupportedPlatform{OS: "unsupported"}
}

// NewLinux creates a new Linux platform (stub for unsupported builds)
func NewLinux() (Platform, error) {
	return nil, &ErrUnsupportedPlatform{OS: "unsupported"}
}
