package scripting

import (
	"go.starlark.net/starlark"
)

// Bindings for exposing daemon state to Starlark

// starlarkGetProcessList returns a list of running processes (stub)
func (s *Service) starlarkGetProcessList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	// STUB: In a real implementation, this would query the process service
	// For now, return a dummy list

	// Create a Dict for the process
	p1 := new(starlark.Dict)
	p1.SetKey(starlark.String("pid"), starlark.MakeInt(1234))
	p1.SetKey(starlark.String("name"), starlark.String("malware.exe"))
	p1.SetKey(starlark.String("user"), starlark.String("root"))

	return starlark.NewList([]starlark.Value{p1}), nil
}

// starlarkIsNetworkActive checks if a port is listening
func (s *Service) starlarkIsNetworkActive(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var port int
	if err := starlark.UnpackArgs(b.Name(), args, kwargs, "port", &port); err != nil {
		return nil, err
	}

	// STUB: Check network service
	return starlark.Bool(false), nil
}

// updateGlobals adds the new bindings to the global dictionary
func (s *Service) updateGlobals() {
	// We can update globals dynamically if needed, or just add them in createGlobals
	// For now, we'll just add them to the initial createGlobals in service.go
	// (requires editing service.go)
}
