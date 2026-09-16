package darkapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRotationResumesAfterLostConfirmation(t *testing.T) {
	confirms, begins := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Device-ID") != "dev_test" {
			t.Error("missing device binding")
		}
		switch r.URL.Path {
		case "/api/v1/endpoints/darkd/credential-rotations":
			begins++
			if r.Header.Get("X-API-Key") != "old" {
				t.Error("wrong begin key")
			}
			json.NewEncoder(w).Encode(map[string]string{"rotation_id": "11111111-1111-4111-8111-111111111111", "api_key": "new", "device_id": "dev_test", "app": "darkd"})
		case "/api/v1/endpoints/darkd/credential-rotations/confirm":
			confirms++
			if r.Header.Get("X-API-Key") != "new" {
				t.Error("wrong confirm key")
			}
			if confirms == 1 {
				http.Error(w, "retry", 503)
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "device_id": "dev_test"})
		default:
			t.Error(r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := SaveCredentials(path, &Credentials{BaseURL: server.URL, DeviceID: "dev_test", DeviceKey: "old"}); err != nil {
		t.Fatal(err)
	}
	client := New(&Config{BaseURL: server.URL, AllowHTTP: true, CredentialFile: path})
	if err := client.RotateCredentials(context.Background(), path); err == nil {
		t.Fatal("lost confirmation must preserve pending credential")
	}
	current, _ := LoadCredentials(path)
	pending, err := LoadCredentials(path + ".rotation")
	if err != nil || current.DeviceKey != "old" || pending.DeviceKey != "new" {
		t.Fatal(current, pending, err)
	}
	if err := client.RotateCredentials(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	current, err = LoadCredentials(path)
	if err != nil || current.DeviceKey != "new" || begins != 1 {
		t.Fatal(current, err, begins)
	}
	if _, err := os.Stat(path + ".rotation"); !os.IsNotExist(err) {
		t.Fatal("pending credential not removed")
	}
}
