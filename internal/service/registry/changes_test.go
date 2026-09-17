package registry

import "testing"

func TestPersistenceChanges(t *testing.T) {
	result := changes(map[string]string{"unchanged": "1", "removed": "2", "modified": "3"}, map[string]string{"unchanged": "1", "added": "4", "modified": "5"})
	if len(result) != 3 {
		t.Fatalf("changes=%v", result)
	}
	for i, action := range []string{"added", "modified", "removed"} {
		if result[i]["action"] != action {
			t.Fatalf("changes=%v", result)
		}
	}
}
