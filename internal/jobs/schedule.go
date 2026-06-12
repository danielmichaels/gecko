package jobs

import (
	"time"

	"github.com/danielmichaels/gecko/internal/store"
)

// FrequencyInterval maps a scan-frequency preset to its cadence interval. It is
// the single source of truth for the preset → duration mapping; the scheduling
// UPDATEs receive only the resulting interval (as seconds) and do the
// now()-relative arithmetic in SQL so jitter stays per-row. ok is false for
// 'off' and for any unrecognized value (fail closed: an unknown preset never
// schedules a scan).
func FrequencyInterval(freq store.ScanFrequency) (time.Duration, bool) {
	switch freq {
	case store.ScanFrequencyHourly:
		return time.Hour, true
	case store.ScanFrequencySixHourly:
		return 6 * time.Hour, true
	case store.ScanFrequencyDaily:
		return 24 * time.Hour, true
	case store.ScanFrequencyWeekly:
		return 7 * 24 * time.Hour, true
	default: // off, or any unknown value
		return 0, false
	}
}

// IsKnownFrequency reports whether freq is one of the defined presets. The
// service validates user input with it before persisting, so an unrecognized
// value is rejected as bad input rather than silently coerced to "off" by
// ScheduleArgs.
func IsKnownFrequency(freq store.ScanFrequency) bool {
	switch freq {
	case store.ScanFrequencyHourly,
		store.ScanFrequencySixHourly,
		store.ScanFrequencyDaily,
		store.ScanFrequencyWeekly,
		store.ScanFrequencyOff:
		return true
	default:
		return false
	}
}

// EffectiveFrequency resolves the cadence that actually applies to a domain: its
// own override when set, otherwise the tenant default. A NULL override (Valid
// false) means "inherit", so the default — including an 'off' default — flows
// through.
func EffectiveFrequency(
	override store.NullScanFrequency,
	tenantDefault store.ScanFrequency,
) store.ScanFrequency {
	if override.Valid {
		return override.ScanFrequency
	}
	return tenantDefault
}

// ScheduleArgs converts an effective frequency into the (base_secs, is_off) pair
// the scheduling UPDATEs consume. is_off true clears the cursor (next_scan_at =
// NULL), pausing the domain; base_secs is then irrelevant and returned as 0.
func ScheduleArgs(freq store.ScanFrequency) (baseSecs float64, isOff bool) {
	d, ok := FrequencyInterval(freq)
	if !ok {
		return 0, true
	}
	return d.Seconds(), false
}
