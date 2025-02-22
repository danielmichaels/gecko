package main

import (
	"fmt"
	kongyaml "github.com/alecthomas/kong-yaml"
	"os"
	"path/filepath"
	"text/template"

	"github.com/danielmichaels/doublestag/internal/cmd"
	"github.com/danielmichaels/doublestag/internal/version"

	"github.com/alecthomas/kong"
)

const appName = "doublestag"

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

	Version VersionFlag   `       help:"Print version information and quit" short:"v" name:"version"`
	Domain  cmd.DomainCmd `cmd:"" help:"Run domain operations"`
	Serve   cmd.ServeCmd  `cmd:"" help:"Run server"`
	Worker  cmd.WorkerCmd `cmd:"" help:"Run jobs worker"`
	Auth    cmd.AuthCmd   `cmd:"" help:"Run auth commands"`
}

func run() error {
	ver := version.Get()
	if ver == "unavailable" {
		ver = "development"
	}
	cli := CLI{
		Version: VersionFlag(ver),
	}
	// Display help if no args are provided instead of an error message
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "--help")
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to get user config dir: %v\n", err)
	}
	defaultConfigPath := filepath.Join(configDir, appName)
	defaultConfigFile := filepath.Join(defaultConfigPath, "config.yaml")
	err = initialiseConfigFile(defaultConfigPath, defaultConfigFile, cli.Globals)
	if err != nil {
		fmt.Println("failed to initialise config file:", err)
		os.Exit(1)
	}

	ctx := kong.Parse(&cli,
		kong.Name(appName),
		kong.Description(fmt.Sprintf("%s is a DNS security tool", appName)),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Configuration(kongyaml.Loader, defaultConfigFile),
		kong.DefaultEnvars(appName),
		kong.Vars{
			"version":     string(cli.Version),
			"config_path": defaultConfigFile,
		})
	err = ctx.Run(&cli.Globals)
	ctx.FatalIfErrorf(err)
	return nil
}

func initialiseConfigFile(configPath, configFileName string, globals cmd.Globals) error {
	if !doesNotExist(configFileName) {
		return nil
	}
	_, _ = fmt.Fprintln(os.Stderr, "config file does not exist. attempting to create it. ")
	err := CreateDirectoryIfNotExist(configPath)
	if err != nil {
		return err
	}
	fd := FileData{globals}
	tfile, err := os.ReadFile("./config.yaml")
	tmpl := template.Must(template.New("config").Parse(string(tfile)))
	err = generateDefaultConfigFile(configFileName, tmpl, fd)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stderr, "config file created at: %s\n", configFileName)
	return nil
}

func doesNotExist(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return true
	}
	return false
}

func CreateDirectoryIfNotExist(dirPath string) error {
	if err := os.Mkdir(dirPath, 0755); err != nil {
		return err
	}
	return nil
}

type FileData struct {
	cmd.Globals
}

func generateDefaultConfigFile(fp string, tmpl *template.Template, data FileData) error {
	if doesNotExist(fp) {
		file, err := os.Create(fp)
		if err != nil {
			return err
		}
		defer file.Close()

		if err := tmpl.Execute(file, data); err != nil {
			return err
		}
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		os.Exit(1)
	}
}
