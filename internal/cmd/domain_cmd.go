package cmd

import (
	"fmt"
	"github.com/danielmichaels/doublestag/internal/jobs"
	"github.com/jackc/pgx/v5"
)

// FIXME: this needs auth with server but for now is unauthenticated
type DomainCmd struct {
	Add    AddDomainCmd    `cmd:"" help:"Add a new domain"`
	Remove RemoveDomainCmd `cmd:"" help:"Remove a domain"`
	List   ListDomainCmd   `cmd:"" help:"List all domains"`
}

type AddDomainCmd struct {
	Name string `arg:"" help:"Domain name to add"`
}

func (a *AddDomainCmd) Run(g *Globals) error {
	setup, err := NewSetup("domain-cli", WithRiver(100, true))
	if err != nil {
		return err
	}
	defer setup.Close()

	// validate user auth
	// validate domain
	// does domain exist in db?
	fmt.Println("Adding domain:", a.Name)

	tx, err := setup.DB.BeginTx(setup.Ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(setup.Ctx)

	_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.EnumerateSubdomainArgs{
		Domain:      a.Name,
		Concurrency: 100,
	}, nil)
	if err != nil {
		return err
	}

	if err := tx.Commit(setup.Ctx); err != nil {
		return err
	}
	return nil
}

type RemoveDomainCmd struct {
	Name string `arg:"" help:"Domain name to remove"`
}

func (r *RemoveDomainCmd) Run(g *Globals) error {
	fmt.Println("Removing domain:", r.Name)
	return nil
}

type ListDomainCmd struct{}

func (l *ListDomainCmd) Run(g *Globals) error {
	fmt.Println("Listing domains")
	return nil
}
