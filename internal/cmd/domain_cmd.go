package cmd

import "fmt"

// FIXME: this needs auth with server but for now is unauthenticated
type DomainCmd struct {
	Add    AddDomainCmd    `cmd:"" help:"Add a new domain"`
	Remove RemoveDomainCmd `cmd:"" help:"Remove a domain"`
	List   ListDomainCmd   `cmd:"" help:"List all domains"`
}

type AddDomainCmd struct {
	Name string `arg:"" help:"Domain name to add"`
}

type RemoveDomainCmd struct {
	Name string `arg:"" help:"Domain name to remove"`
}
type ListDomainCmd struct{}

func (a *AddDomainCmd) Run(g *Globals) error {
	fmt.Println("Adding domain:", a.Name)
	return nil
}

func (r *RemoveDomainCmd) Run(g *Globals) error {
	fmt.Println("Removing domain:", r.Name)
	return nil
}

func (l *ListDomainCmd) Run(g *Globals) error {
	fmt.Println("Listing domains")
	return nil
}
