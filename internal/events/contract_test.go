package events

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedEndpointContract(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/endpoint-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []json.RawMessage
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, raw := range rows {
		var envelope struct {
			Event json.RawMessage `json:"event"`
		}
		if err = json.Unmarshal(raw, &envelope); err != nil {
			t.Fatal(err)
		}
		raw = envelope.Event
		var value Event
		if err = json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		event := value
		if event.SchemaVersion != 2 || event.BootID != "boot-fixture" || event.Sequence != 1 || event.Entities["process"] == nil || len(event.Facts) == 0 {
			t.Fatalf("contract lost: %+v", event)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var replay Event
		if err = json.Unmarshal(encoded, &replay); err != nil {
			t.Fatal(err)
		}
	}
}
