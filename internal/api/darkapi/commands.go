package darkapi

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"time"
)

type ResponseCommand struct {
	ID         string                 `json:"id"`
	DeviceID   string                 `json:"device_id"`
	App        string                 `json:"app"`
	Action     string                 `json:"action"`
	Params     map[string]interface{} `json:"params"`
	ExpiresAt  time.Time              `json:"expires_at"`
	LeaseToken string                 `json:"lease_token"`
}

func (c *Client) ClaimCommand(ctx context.Context) (*ResponseCommand, error) {
	var response struct {
		Command *ResponseCommand `json:"command"`
	}
	if err := c.request(ctx, "POST", "/api/v1/endpoints/darkd/commands/claim", "device", map[string]interface{}{}, &response, false); err != nil {
		return nil, err
	}
	command := response.Command
	if command == nil {
		return nil, nil
	}
	_, idErr := uuid.Parse(command.ID)
	_, leaseErr := uuid.Parse(command.LeaseToken)
	if idErr != nil || leaseErr != nil || command.DeviceID != c.deviceID || command.App != "darkd" || len(command.Params) != 0 || !command.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("invalid or expired command")
	}
	return command, nil
}
func (c *Client) AckCommand(ctx context.Context, command *ResponseCommand, status string, result interface{}) error {
	var response struct {
		Success bool   `json:"success"`
		ID      string `json:"command_id"`
	}
	err := c.request(ctx, "POST", "/api/v1/endpoints/darkd/commands/"+command.ID+"/ack", "device", map[string]interface{}{"status": status, "result": result, "lease_token": command.LeaseToken}, &response, false)
	if err != nil {
		return err
	}
	if !response.Success || response.ID != command.ID {
		return fmt.Errorf("command acknowledgment mismatch")
	}
	return nil
}
