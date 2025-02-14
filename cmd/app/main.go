package main

import (
	"fmt"
	"github.com/danielmichaels/doublestag/internal/cmd"
	"os"

	"github.com/alecthomas/kong"
)

const appName = "doublestag"

var version string

type VersionFlag string

func (v VersionFlag) Decode(_ *kong.DecodeContext) error { return nil }
func (v VersionFlag) IsBool() bool                       { return true }
func (v VersionFlag) BeforeApply(app *kong.Kong, vars kong.Vars) error {
	fmt.Println(vars["version"])
	app.Exit(0)
	return nil
}

type CLI struct {
	cmd.Globals

	Serve   cmd.ServeCmd  `cmd:"" help:"Run server."`
	Worker  cmd.WorkerCmd `cmd:"" help:"Run workers."`
	Version VersionFlag   `       help:"Print version information and quit" short:"v" name:"version"`
}

func run() error {
	if version == "" {
		version = "development"
	}
	cli := CLI{
		Version: VersionFlag(version),
	}
	// Display help if no args are provided instead of an error message
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "--help")
	}

	ctx := kong.Parse(&cli,
		kong.Name(appName),
		kong.Description("Doublestag is a DNS security tool"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.DefaultEnvars(appName),
		kong.Vars{
			"version": string(cli.Version),
		})
	err := ctx.Run(&cli.Globals)
	ctx.FatalIfErrorf(err)
	return nil
}

func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
