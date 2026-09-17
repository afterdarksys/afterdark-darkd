package registry

import "sort"

func changes(before, after map[string]string) []map[string]string {
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	ordered := make([]string, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	result := make([]map[string]string, 0)
	for _, key := range ordered {
		old, existed := before[key]
		current, exists := after[key]
		if existed == exists && old == current {
			continue
		}
		action := "modified"
		if !existed {
			action = "added"
		}
		if !exists {
			action = "removed"
		}
		result = append(result, map[string]string{"key": key, "action": action, "previous_digest": old, "current_digest": current})
	}
	return result
}
