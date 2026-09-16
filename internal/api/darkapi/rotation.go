package darkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// RotateCredentials preserves a protected pending key before invalidating the old
// credential. A subsequent call resumes confirmation after a process failure.
func (c *Client) RotateCredentials(ctx context.Context, path string) error {
	return c.rotateCredentials(ctx, path, true)
}
func (c *Client) rotateCredentials(ctx context.Context, path string, recoverExpired bool) error {
	current, err := LoadCredentials(path)
	if err != nil {
		return err
	}
	if current.DeviceID != c.deviceID || current.DeviceKey == "" {
		return fmt.Errorf("credential identity mismatch")
	}
	pendingPath := path + ".rotation"
	pending, err := LoadCredentials(pendingPath)
	if errors.Is(err, os.ErrNotExist) {
		var response struct {
			RotationID string `json:"rotation_id"`
			APIKey     string `json:"api_key"`
			DeviceID   string `json:"device_id"`
			App        string `json:"app"`
		}
		if err = c.request(ctx, "POST", "/api/v1/endpoints/darkd/credential-rotations", "device", map[string]interface{}{}, &response, false); err != nil {
			return err
		}
		if response.DeviceID != c.deviceID || response.App != "darkd" || response.APIKey == "" || len(response.RotationID) != 36 {
			return fmt.Errorf("invalid rotation response")
		}
		value := *current
		pending = &value
		pending.DeviceKey = response.APIKey
		pending.RotationID = response.RotationID
		data, err := json.Marshal(pending)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(pendingPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		if err = secureCredentialFile(pendingPath); err == nil {
			_, err = f.Write(data)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = syncCredentialDirectory(pendingPath); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if pending.DeviceID != current.DeviceID || pending.BaseURL != current.BaseURL || pending.RotationID == "" {
		return fmt.Errorf("pending rotation identity mismatch")
	}
	next := *c
	next.deviceKey = pending.DeviceKey
	var response struct {
		Success  bool   `json:"success"`
		DeviceID string `json:"device_id"`
	}
	if err = next.request(ctx, "POST", "/api/v1/endpoints/darkd/credential-rotations/confirm", "device", map[string]string{"rotation_id": pending.RotationID}, &response, false); err != nil {
		var apiErr *APIError
		if recoverExpired && errors.As(err, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 409) && c.Heartbeat(ctx) == nil {
			// The old key still authenticates: the pending key was never activated.
			if removeErr := os.Remove(pendingPath); removeErr != nil {
				return removeErr
			}
			if syncErr := syncCredentialDirectory(path); syncErr != nil {
				return syncErr
			}
			return c.rotateCredentials(ctx, path, false)
		}
		return fmt.Errorf("pending rotation retained: %w", err)
	}
	if !response.Success || response.DeviceID != c.deviceID {
		return fmt.Errorf("rotation acknowledgment mismatch")
	}
	pending.RotationID = ""
	if err = SaveCredentials(path, pending); err != nil {
		return fmt.Errorf("new key active; rerun rotation to recover pending credential: %w", err)
	}
	if err = os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncCredentialDirectory(path)
}
