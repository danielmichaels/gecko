package jobs

import "testing"

func TestEnumerationWorkers(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		fallback int
		want     int
	}{
		{name: "explicit count used", env: "3", fallback: 100, want: 3},
		{name: "zero falls back to general worker count", env: "0", fallback: 42, want: 42},
		{name: "negative falls back", env: "-1", fallback: 7, want: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("ENUMERATION_WORKER_COUNT", tt.env)
			if got := enumerationWorkers(tt.fallback); got != tt.want {
				t.Fatalf("enumerationWorkers(%d) = %d, want %d", tt.fallback, got, tt.want)
			}
		})
	}
}
