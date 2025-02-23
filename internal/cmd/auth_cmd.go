package cmd

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type AuthCmd struct {
	Login  LoginCmd  `cmd:"" help:"Login to doublestag server"`
	Logout LogoutCmd `cmd:"" help:"Logout from doublestag server"`
	Status StatusCmd `cmd:"" help:"Show authentication status"`
}

type LoginCmd struct{}

func (l *LoginCmd) Run(g *Globals, ac *AuthCmd) error {
	if g.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	if g.Username == "" {
		return fmt.Errorf("username is required")
	}
	if g.Password == "" {
		return fmt.Errorf("password is required")
	}
	config := map[string]interface{}{
		"server": map[string]string{
			"url":      g.ServerURL,
			"username": g.Username,
			"password": g.Password,
		},
	}

	yamlData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(string(g.ConfigFile), yamlData, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	fmt.Printf("Successfully logged in to %s\n", g.ServerURL)
	return nil
}

type LogoutCmd struct{}

func (l *LogoutCmd) Run(ac *AuthCmd) error {
	// TODO: implement logout logic
	return nil
}

type StatusCmd struct{}

func (s *StatusCmd) Run(ac *AuthCmd) error {
	// TODO: implement status logic
	return nil
}
