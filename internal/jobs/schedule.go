package jobs

import (
	"time"

	"github.com/danielmichaels/gecko/internal/store"
)

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
	default:
		return 0, false
	}
}

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

func EffectiveFrequency(
	override store.NullScanFrequency,
	tenantDefault store.ScanFrequency,
) store.ScanFrequency {
	if override.Valid {
		return override.ScanFrequency
	}
	return tenantDefault
}

func ScheduleArgs(freq store.ScanFrequency) (baseSecs float64, isOff bool) {
	d, ok := FrequencyInterval(freq)
	if !ok {
		return 0, true
	}
	return d.Seconds(), false
}
