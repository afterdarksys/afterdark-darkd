//go:build !windows

package etw

import "go.uber.org/zap"

type Session struct{}

func NewSession(name string, logger *zap.Logger) *Session {
	return &Session{}
}

func (s *Session) Start() error {
	return nil
}

func (s *Session) Stop() error {
	return nil
}
