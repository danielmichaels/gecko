package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
)

// newTestParser builds the CLI parser the same way run() does so flag/env
// resolution (DefaultEnvars, yaml config) matches production.
func newTestParser(t *testing.T, cli *CLI) *kong.Kong {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	k, err := kong.New(cli,
		kong.Name(appName),
		kong.DefaultEnvars(appName),
		kong.Configuration(kongyaml.Loader, cfg),
		kong.Vars{"version": "test", "config_path": cfg},
	)
	if err != nil {
		t.Fatalf("kong.New: %v", err)
	}
	return k
}

// An explicit --password on `auth bootstrap` must reach BootstrapCmd.Password and
// win over the GECKO_PASSWORD env var. Regression guard for the duplicate-flag
// collision between Globals.Password and BootstrapCmd.Password.
func TestBootstrapPasswordFlagWinsOverEnv(t *testing.T) {
	t.Setenv("GECKO_PASSWORD", "envpass")
	t.Setenv("GECKO_USERNAME", "envuser")

	var cli CLI
	k := newTestParser(t, &cli)
	if _, err := k.Parse([]string{
		"auth", "bootstrap",
		"--email", "owner@example.com",
		"--password", "clipass",
		"--tenant-name", "Acme",
	}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got := cli.Auth.Bootstrap.Password; got != "clipass" {
		t.Errorf(
			"bootstrap password = %q, want %q (env GECKO_PASSWORD must not shadow the flag)",
			got,
			"clipass",
		)
	}
	if got := cli.Auth.Bootstrap.Email; got != "owner@example.com" {
		t.Errorf("bootstrap email = %q, want %q", got, "owner@example.com")
	}
}

// `auth login` keeps its own --username/--password (env-bindable) after the flags
// move off Globals.
func TestLoginCredentialsParse(t *testing.T) {
	t.Setenv("GECKO_USERNAME", "envuser@example.com")
	t.Setenv("GECKO_PASSWORD", "envpass")

	var cli CLI
	k := newTestParser(t, &cli)
	if _, err := k.Parse([]string{"auth", "login"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cli.Auth.Login.Username != "envuser@example.com" {
		t.Errorf("login username = %q, want env value", cli.Auth.Login.Username)
	}
	if cli.Auth.Login.Password != "envpass" {
		t.Errorf("login password = %q, want env value", cli.Auth.Login.Password)
	}
}
