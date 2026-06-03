package observer

import (
	"reflect"
	"testing"
)

// planSync generalizes the diff to rich record types: a key present in both the
// observed and current sets but with a changed payload is an "updated", not just
// unchanged. Deletions remain gated on `authoritative`.
func TestPlanSync(t *testing.T) {
	tests := []struct {
		name          string
		observed      map[string]string
		current       map[string]string
		authoritative bool
		wantCreated   []string
		wantUpdated   []string
		wantDeleted   []string
	}{
		{
			name:        "created: new key",
			observed:    map[string]string{"k1": "p1", "k2": "p2"},
			current:     map[string]string{"k1": "p1"},
			wantCreated: []string{"k2"},
		},
		{
			name:          "updated: same key, changed payload",
			observed:      map[string]string{"k1": "new"},
			current:       map[string]string{"k1": "old"},
			authoritative: true,
			wantUpdated:   []string{"k1"},
		},
		{
			name:          "unchanged: same key and payload",
			observed:      map[string]string{"k1": "p1"},
			current:       map[string]string{"k1": "p1"},
			authoritative: true,
		},
		{
			name:          "deleted: authoritative absence",
			observed:      map[string]string{"k1": "p1"},
			current:       map[string]string{"k1": "p1", "k2": "p2"},
			authoritative: true,
			wantDeleted:   []string{"k2"},
		},
		{
			name:          "indeterminate: empty observed must NOT delete",
			observed:      map[string]string{},
			current:       map[string]string{"k1": "p1", "k2": "p2"},
			authoritative: false,
		},
		{
			name:          "mixed create/update/delete",
			observed:      map[string]string{"k2": "p2new", "k3": "p3"},
			current:       map[string]string{"k1": "p1", "k2": "p2old"},
			authoritative: true,
			wantCreated:   []string{"k3"},
			wantUpdated:   []string{"k2"},
			wantDeleted:   []string{"k1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created, updated, deleted := planSync(tt.observed, tt.current, tt.authoritative)
			if !reflect.DeepEqual(created, tt.wantCreated) {
				t.Errorf("created = %v, want %v", created, tt.wantCreated)
			}
			if !reflect.DeepEqual(updated, tt.wantUpdated) {
				t.Errorf("updated = %v, want %v", updated, tt.wantUpdated)
			}
			if !reflect.DeepEqual(deleted, tt.wantDeleted) {
				t.Errorf("deleted = %v, want %v", deleted, tt.wantDeleted)
			}
		})
	}
}
