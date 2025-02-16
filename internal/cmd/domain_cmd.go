package cmd

import (
	"fmt"
	"github.com/danielmichaels/doublestag/internal/jobs"
	"github.com/danielmichaels/doublestag/internal/scanner"
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

	fmt.Println("Adding domain:", a.Name)
	domain := a.Name // no validation done yet
	dnsClient := scanner.NewDNSClient()
	if r, ok := dnsClient.LookupA(domain + "."); ok {
		fmt.Printf("A records: %v\n", r)
	}
	if r, ok := dnsClient.LookupAAAA(domain + "."); ok {
		fmt.Printf("AAAA records: %v\n", r)
	}
	if r, ok := dnsClient.LookupCNAME(domain + "."); ok {
		fmt.Printf("CNAME records: %v\n", r)
	}
	if r, ok := dnsClient.LookupTXT(domain + "."); ok {
		fmt.Printf("TXT records: %v\n", r)
	}
	if r, ok := dnsClient.LookupNS(domain + "."); ok {
		fmt.Printf("NS records: %v\n", r)
	}
	if r, ok := dnsClient.LookupMX(domain + "."); ok {
		fmt.Printf("MX records: %v\n", r)
	}
	//
	//output, err := dnsClient.EnumerateWithSubfinder(context.Background(), domain, 100)
	//if err != nil {
	//	return fmt.Errorf("EnumerateWithSubfinder: %w", err)
	//}
	//
	//if err := scanner.ProcessSubdomainResults(output, func(r scanner.SubdomainResult) error {
	//	if err := scanner.RecordHandler(r); err != nil {
	//		return fmt.Errorf("RecordHandler: %w", err)
	//	}
	//	return nil
	//}); err != nil {
	//	return fmt.Errorf("ProcessSubdomainResults: %w", err)
	//}
	// --- Example of enqueuing a job ---
	// This section demonstrates how to enqueue a job after the domain
	// processing is complete.  This is a *hypothetical* example; you'd
	// replace this with your actual job and arguments.
	tx, err := setup.DB.BeginTx(setup.Ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(setup.Ctx) // Ensure rollback if no commit.

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
