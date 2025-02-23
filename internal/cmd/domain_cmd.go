package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/carlmjohnson/requests"
	"github.com/danielmichaels/gecko/internal/dto"
)

// FIXME: this needs auth with server but for now is unauthenticated
type DomainCmd struct {
	Add     AddDomainCmd    `cmd:"" help:"Add a new domain"`
	Get     DomainGetCmd    `cmd:"" help:"Get a domain by ID"`
	Update  UpdateDomainCmd `cmd:"" help:"Update a domain by ID"`
	Remove  RemoveDomainCmd `cmd:"" help:"Remove a domain"`
	List    ListDomainCmd   `cmd:"" help:"List all domains"`
	Verbose bool            `help:"Increase verbosity (shows logs)" default:"false"`
}

type AddDomainCmd struct {
	Name string `arg:"" help:"Domain name to add"`
}

func (a *AddDomainCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()
	var domain dto.Domain
	err := requests.
		URL(g.ServerURL + "/api/domains").
		BodyJSON(map[string]string{"domain": a.Name}).
		ToJSON(&domain).
		Fetch(ctx)
	if err != nil {
		return err
	}
	fmt.Println(formatOutput(domain, g.Format))

	//opts := []SetupOption{
	//	WithRiver(100, true),
	//}
	//if !dc.Verbose {
	//	opts = append(opts, WithSilentLogging())
	//}
	//setup, err := NewSetup("domain-cli", opts...)
	//if err != nil {
	//	return err
	//}
	//defer setup.Close()
	//
	//// validate user auth
	//// validate domain
	//// does domain exist in db?
	//fmt.Println("Adding domain:", a.Name)
	//
	//tx, err := setup.DB.BeginTx(setup.Ctx, pgx.TxOptions{})
	//if err != nil {
	//	return err
	//}
	//defer func(tx pgx.Tx, ctx context.Context) {
	//	_ = tx.Rollback(ctx)
	//}(tx, setup.Ctx)

	//_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.ScanCertificateArgs{
	//	Domain: a.Name,
	//}, nil)
	//if err != nil {
	//	return err
	//}
	//_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.ScanCNAMEArgs{
	//	Domain: a.Name,
	//}, nil)
	//if err != nil {
	//	return err
	//}
	//_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.ResolveDomainArgs{
	//	Domain: a.Name,
	//}, nil)
	//if err != nil {
	//	return err
	//}
	//_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.ScanZoneTransferArgs{
	//	Domain: a.Name,
	//}, nil)
	//if err != nil {
	//	return err
	//}
	//_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.ScanDNSSECArgs{
	//	Domain: a.Name,
	//}, nil)
	//if err != nil {
	//	return err
	//}
	//_, err = setup.RC.InsertTx(setup.Ctx, tx, jobs.EnumerateSubdomainArgs{
	//	Domain:      a.Name,
	//	Concurrency: 100,
	//}, nil)
	//if err != nil {
	//	return err
	//}

	//if err := tx.Commit(setup.Ctx); err != nil {
	//	return err
	//}
	return nil
}

type DomainGetCmd struct {
	ID string `arg:"" help:"Domain ID to get" example:"domain_00000001"`
}

func (d *DomainGetCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()
	var domain dto.Domain
	err := requests.
		URL(g.ServerURL + "/api/domains/" + d.ID).
		ToJSON(&domain).
		Fetch(ctx)
	if err != nil {
		return HandleRequestError(err, g.ServerURL)
	}

	fmt.Println(formatOutput(domain, g.Format))
	return nil
}

type UpdateDomainCmd struct {
	ID         string `arg:"" required:"" help:"Domain ID to update"`
	DomainType string `flag:"" help:"Domain type to update, options: tld,subdomain,wildcard"`
	Status     string `flag:"" help:"Domain status to update, options: active,inactive"`
}

func (d *UpdateDomainCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()
	if d.Status == "" && d.DomainType == "" {
		return fmt.Errorf("must provide at least one of status or domain_type")
	}
	body := map[string]string{"source": "user_supplied"}
	if d.DomainType != "" {
		body["domain_type"] = d.DomainType
	}
	if d.Status != "" {
		body["status"] = d.Status
	}
	var domain dto.Domain
	if err := requests.
		URL(g.ServerURL + "/api/domains/" + d.ID).
		Method(http.MethodPut).
		BodyJSON(body).
		ToJSON(&domain).
		Fetch(ctx); err != nil {
		return HandleRequestError(err, g.ServerURL)
	}

	fmt.Println(formatOutput(domain, g.Format))
	return nil
}

type RemoveDomainCmd struct {
	DomainID string `arg:"" required:"" help:"Domain ID to remove" placeholder:"domain_00000001"`
	Force    bool   `help:"Force remove domain"`
}

func (d *RemoveDomainCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()
	if !d.Force {
		fmt.Println("Are you sure? [y/N]")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			fmt.Println("Delete cancelled.")
			return nil
		}
	}

	if err := requests.
		URL(g.ServerURL + "/api/domains/" + d.DomainID).
		Method("DELETE").
		Fetch(ctx); err != nil {
		return HandleRequestError(err, g.ServerURL)
	}

	if g.Format == "json" {
		result := map[string]string{
			"status":    "success",
			"message":   "Domain deleted successfully",
			"domain_id": d.DomainID,
		}
		jsonOutput, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonOutput))
	} else {
		fmt.Printf("Successfully deleted domain with ID: %s\n", d.DomainID)
	}
	return nil
}

type ListDomainCmd struct{}

func (d *ListDomainCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()

	var domains struct {
		Domains []dto.Domain `json:"domains"`
	}
	if err := requests.
		URL(g.ServerURL + "/api/domains").
		ToJSON(&domains).
		Fetch(ctx); err != nil {
		return HandleRequestError(err, g.ServerURL)
	}

	if len(domains.Domains) == 0 {
		fmt.Println("No domains found.")
		return nil
	}

	if g.Format == "json" {
		fmt.Println(formatOutput(domains, g.Format))
	} else {
		fmt.Println(formatOutput(domains.Domains, g.Format))
	}

	return nil
}
