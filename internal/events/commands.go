package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

type CommandReceipt struct {
	ID, Action, Status string
	Result             json.RawMessage
}

func (s *Store) CommandReceipt(ctx context.Context, id string) (*CommandReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, fmt.Errorf("event store unavailable")
	}
	receipt := &CommandReceipt{ID: id}
	err := s.db.QueryRowContext(ctx, "SELECT action,status,result FROM command_results WHERE id=?", id).Scan(&receipt.Action, &receipt.Status, &receipt.Result)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return receipt, err
}

// CompleteCommand commits an optional canary and receipt together before remote acknowledgment.
func (s *Store) CompleteCommand(ctx context.Context, receipt CommandReceipt, event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return fmt.Errorf("event store unavailable")
	}
	if len(receipt.Result) > 65536 || !json.Valid(receipt.Result) {
		return fmt.Errorf("invalid command result")
	}
	if event != nil {
		event.ID = receipt.ID
		return s.publishLocked(ctx, *event, &receipt)
	}
	_, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO command_results(id,action,result,status) VALUES(?,?,?,?)", receipt.ID, receipt.Action, receipt.Result, receipt.Status)
	return err
}
