package dnsclient

import (
	"context"
	"reflect"
	"testing"

	"github.com/danielmichaels/gecko/internal/config"
	"github.com/projectdiscovery/subfinder/v2/pkg/resolve"
)

func TestBuildSubfinderOptions(t *testing.T) {
	cfg := &config.Conf{}
	cfg.AppConf.SubfinderRateLimit = 50
	cfg.AppConf.SubfinderTimeout = 45
	cfg.AppConf.SubfinderMaxTime = 7
	cfg.AppConf.SubfinderSources = []string{"crtsh", "github"}
	cfg.AppConf.SubfinderExcludeSources = []string{"alienvault"}

	var called bool
	callback := func(*resolve.HostEntry) { called = true }

	opts := buildSubfinderOptions(cfg, 25, callback)

	if opts.RateLimit != 50 {
		t.Errorf("RateLimit = %d, want 50", opts.RateLimit)
	}
	if opts.Timeout != 45 {
		t.Errorf("Timeout = %d, want 45", opts.Timeout)
	}
	if opts.MaxEnumerationTime != 7 {
		t.Errorf("MaxEnumerationTime = %d, want 7", opts.MaxEnumerationTime)
	}
	if opts.Threads != 25 {
		t.Errorf("Threads = %d, want 25 (from concurrency arg)", opts.Threads)
	}
	if !opts.Silent {
		t.Errorf("Silent = false, want true")
	}
	if opts.JSON {
		t.Errorf("JSON = true, want false")
	}
	if !reflect.DeepEqual([]string(opts.Sources), []string{"crtsh", "github"}) {
		t.Errorf("Sources = %v, want [crtsh github]", opts.Sources)
	}
	if !reflect.DeepEqual([]string(opts.ExcludeSources), []string{"alienvault"}) {
		t.Errorf("ExcludeSources = %v, want [alienvault]", opts.ExcludeSources)
	}
	if opts.ResultCallback == nil {
		t.Fatalf("ResultCallback = nil, want callback wired")
	}
	opts.ResultCallback(&resolve.HostEntry{})
	if !called {
		t.Errorf("ResultCallback did not invoke the provided callback")
	}
}

func TestEnumerateWithSubfinderCallbackDisabledShortCircuits(t *testing.T) {
	t.Setenv("SUBFINDER_ENABLED", "false")

	c := New()

	var called bool
	err := c.EnumerateWithSubfinderCallback(
		context.Background(),
		"example.com",
		10,
		func(*resolve.HostEntry) { called = true },
	)
	if err != nil {
		t.Fatalf("disabled enumeration returned err = %v, want nil", err)
	}
	if called {
		t.Errorf(
			"callback invoked while subfinder disabled; expected short-circuit before any enumeration",
		)
	}
}

func TestBuildSubfinderOptionsEmptySourcesStayNil(t *testing.T) {
	cfg := &config.Conf{}
	cfg.AppConf.SubfinderSources = []string{}
	cfg.AppConf.SubfinderExcludeSources = nil

	opts := buildSubfinderOptions(cfg, 10, func(*resolve.HostEntry) {})

	if opts.Sources != nil {
		t.Errorf("Sources = %v, want nil so subfinder uses its default source set", opts.Sources)
	}
	if opts.ExcludeSources != nil {
		t.Errorf("ExcludeSources = %v, want nil", opts.ExcludeSources)
	}
}
