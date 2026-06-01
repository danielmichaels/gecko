package observer

import (
	"reflect"
	"testing"
)

// planChanges is the pure heart of the recorder: given the authoritatively
// observed key set and the current projection key set, decide what to create and
// what to delete. Deletions are gated on `authoritative` so a transient
// SERVFAIL/timeout (which yields an empty observed set but authoritative=false)
// can never emit phantom deletions.
func TestPlanChanges(t *testing.T) {
	tests := []struct {
		name          string
		observed      []string
		current       []string
		authoritative bool
		wantCreated   []string
		wantDeleted   []string
	}{
		{
			name:        "created: new key not yet in projection",
			observed:    []string{"1.1.1.1", "2.2.2.2"},
			current:     []string{"1.1.1.1"},
			wantCreated: []string{"2.2.2.2"},
			wantDeleted: nil,
		},
		{
			name:          "deleted: authoritative absence of a current key",
			observed:      []string{"1.1.1.1"},
			current:       []string{"1.1.1.1", "2.2.2.2"},
			authoritative: true,
			wantCreated:   nil,
			wantDeleted:   []string{"2.2.2.2"},
		},
		{
			name:          "unchanged: key in both sets yields nothing",
			observed:      []string{"1.1.1.1"},
			current:       []string{"1.1.1.1"},
			authoritative: true,
			wantCreated:   nil,
			wantDeleted:   nil,
		},
		{
			name:          "indeterminate: empty observed set must NOT delete",
			observed:      nil,
			current:       []string{"1.1.1.1", "2.2.2.2"},
			authoritative: false,
			wantCreated:   nil,
			wantDeleted:   nil,
		},
		{
			name:          "authoritative empty: all current keys deleted",
			observed:      nil,
			current:       []string{"1.1.1.1", "2.2.2.2"},
			authoritative: true,
			wantCreated:   nil,
			wantDeleted:   []string{"1.1.1.1", "2.2.2.2"},
		},
		{
			name:          "mixed create and delete",
			observed:      []string{"2.2.2.2", "3.3.3.3"},
			current:       []string{"1.1.1.1", "2.2.2.2"},
			authoritative: true,
			wantCreated:   []string{"3.3.3.3"},
			wantDeleted:   []string{"1.1.1.1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created, deleted := planChanges(tt.observed, tt.current, tt.authoritative)
			if !reflect.DeepEqual(created, tt.wantCreated) {
				t.Errorf("created = %v, want %v", created, tt.wantCreated)
			}
			if !reflect.DeepEqual(deleted, tt.wantDeleted) {
				t.Errorf("deleted = %v, want %v", deleted, tt.wantDeleted)
			}
		})
	}
}
