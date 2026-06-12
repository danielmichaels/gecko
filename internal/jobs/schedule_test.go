package jobs

import (
	"testing"
	"time"

	"github.com/danielmichaels/gecko/internal/store"
)

func TestFrequencyInterval(t *testing.T) {
	tests := []struct {
		name    string
		freq    store.ScanFrequency
		wantDur time.Duration
		wantOK  bool
	}{
		{"hourly", store.ScanFrequencyHourly, time.Hour, true},
		{"six_hourly", store.ScanFrequencySixHourly, 6 * time.Hour, true},
		{"daily", store.ScanFrequencyDaily, 24 * time.Hour, true},
		{"weekly", store.ScanFrequencyWeekly, 7 * 24 * time.Hour, true},
		{"off has no interval", store.ScanFrequencyOff, 0, false},
		{"unknown fails closed", store.ScanFrequency("bogus"), 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := FrequencyInterval(tt.freq)
			if got != tt.wantDur || ok != tt.wantOK {
				t.Errorf(
					"FrequencyInterval(%q) = (%v, %v), want (%v, %v)",
					tt.freq, got, ok, tt.wantDur, tt.wantOK,
				)
			}
		})
	}
}

func TestEffectiveFrequency(t *testing.T) {
	tests := []struct {
		name     string
		override store.NullScanFrequency
		def      store.ScanFrequency
		want     store.ScanFrequency
	}{
		{
			name:     "no override inherits the tenant default",
			override: store.NullScanFrequency{},
			def:      store.ScanFrequencyDaily,
			want:     store.ScanFrequencyDaily,
		},
		{
			name: "override wins over the default",
			override: store.NullScanFrequency{
				ScanFrequency: store.ScanFrequencyWeekly,
				Valid:         true,
			},
			def:  store.ScanFrequencyDaily,
			want: store.ScanFrequencyWeekly,
		},
		{
			name:     "an explicit off override wins over an active default",
			override: store.NullScanFrequency{ScanFrequency: store.ScanFrequencyOff, Valid: true},
			def:      store.ScanFrequencyDaily,
			want:     store.ScanFrequencyOff,
		},
		{
			name:     "inheriting an off default yields off",
			override: store.NullScanFrequency{},
			def:      store.ScanFrequencyOff,
			want:     store.ScanFrequencyOff,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EffectiveFrequency(tt.override, tt.def); got != tt.want {
				t.Errorf(
					"EffectiveFrequency(%+v, %q) = %q, want %q",
					tt.override, tt.def, got, tt.want,
				)
			}
		})
	}
}

func TestIsKnownFrequency(t *testing.T) {
	known := []store.ScanFrequency{
		store.ScanFrequencyHourly,
		store.ScanFrequencySixHourly,
		store.ScanFrequencyDaily,
		store.ScanFrequencyWeekly,
		store.ScanFrequencyOff,
	}
	for _, f := range known {
		if !IsKnownFrequency(f) {
			t.Errorf("IsKnownFrequency(%q) = false, want true", f)
		}
	}
	for _, f := range []store.ScanFrequency{"", "bogus", "DAILY", "monthly"} {
		if IsKnownFrequency(f) {
			t.Errorf("IsKnownFrequency(%q) = true, want false", f)
		}
	}
}

func TestScheduleArgs(t *testing.T) {
	tests := []struct {
		name      string
		freq      store.ScanFrequency
		wantSecs  float64
		wantIsOff bool
	}{
		{"daily -> 86400s active", store.ScanFrequencyDaily, 86400, false},
		{"hourly -> 3600s active", store.ScanFrequencyHourly, 3600, false},
		{"weekly -> 604800s active", store.ScanFrequencyWeekly, 604800, false},
		{"off -> paused", store.ScanFrequencyOff, 0, true},
		{"unknown -> paused (fail closed)", store.ScanFrequency("bogus"), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secs, isOff := ScheduleArgs(tt.freq)
			if secs != tt.wantSecs || isOff != tt.wantIsOff {
				t.Errorf(
					"ScheduleArgs(%q) = (%v, %v), want (%v, %v)",
					tt.freq, secs, isOff, tt.wantSecs, tt.wantIsOff,
				)
			}
		})
	}
}
