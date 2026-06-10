package server

import "testing"

func TestGetPageSize(t *testing.T) {
	tests := []struct {
		name string
		in   int32
		want int32
	}{
		{"zero defaults", 0, 25},
		{"negative defaults", -5, 25},
		{"below max passes through", 50, 50},
		{"at max passes through", maxPageSize, maxPageSize},
		{"above max is clamped", 1_000_000, maxPageSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PaginationQuery{PageSize: tt.in}
			if got := p.GetPageSize(); got != tt.want {
				t.Errorf("GetPageSize(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
