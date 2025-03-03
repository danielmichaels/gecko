package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/danielmichaels/gecko/internal/server"

	"github.com/danielgtaylor/huma/v2"

	"github.com/carlmjohnson/requests"
	"github.com/danielmichaels/gecko/internal/dto"
)

// FIXME: this needs auth with server but for now is unauthenticated
type DomainCmd struct {
	Add     AddDomainCmd     `cmd:"" help:"Add a new domain. Duplicate domains are ignored. Use 'domain scan <domainID>' to re-scan a previously added domain"`
	Update  UpdateDomainCmd  `cmd:"" help:"Update a domain by ID"`
	Records DomainRecordsCmd `cmd:"" help:"List all domain records for a domain"`
	Get     DomainGetCmd     `cmd:"" help:"Get a domain by ID"`
	Remove  RemoveDomainCmd  `cmd:"" help:"Remove a domain"`
	List    ListDomainCmd    `cmd:"" help:"List all domains"`
	Verbose bool             `help:"Increase verbosity (shows logs)" default:"false"`
}

type AddDomainCmd struct {
	Name       string `arg:"" help:"Domain name to add"`
	DomainType string `help:"The type of the domain" default:"tld" enum:"tld,subdomain,wildcard"`
	Status     string `help:"The status of the domain" default:"active" enum:"active,inactive"`
}

func (d *AddDomainCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()

	body := map[string]string{"source": "user_supplied", "domain": d.Name}
	if d.DomainType != "" {
		body["domain_type"] = d.DomainType
	}
	if d.Status != "" {
		body["status"] = d.Status
	}
	var apiErr huma.ErrorModel
	var domain dto.Domain

	err := requestWithSpinner(ctx, "Adding domain...", func() *requests.Builder {
		return requests.
			URL(g.ServerURL + "/api/domains").
			BodyJSON(body).
			ToJSON(&domain).
			ErrorJSON(&apiErr)
	})
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
		return HandleRequestError(err, g.ServerURL)
	}
	fmt.Println(formatOutput(domain, g.Format))
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

	var apiErr huma.ErrorModel
	var domain dto.Domain

	err := requestWithSpinner(ctx, "Fetching domain...", func() *requests.Builder {
		return requests.
			URL(g.ServerURL + "/api/domains/" + d.ID).
			ToJSON(&domain).
			ErrorJSON(&apiErr)
	})
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
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
	var apiErr huma.ErrorModel
	var domain dto.Domain
	err := requestWithSpinner(ctx, "Updating domain...", func() *requests.Builder {
		return requests.
			URL(g.ServerURL + "/api/domains/" + d.ID).
			Method(http.MethodPut).
			BodyJSON(body).
			ToJSON(&domain).
			ErrorJSON(&apiErr)
	})
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
		return HandleRequestError(err, g.ServerURL)
	}

	fmt.Println(formatOutput(domain, g.Format))
	return nil
}

type RemoveDomainCmd struct {
	DomainID string `arg:"" required:"" help:"Domain ID to remove" placeholder:"domain_00000001"`
	Force    bool   `help:"Force remove domain"`
	DryRun   bool   `help:"Dry run, do not remove domain"`
}
type CountResponse struct {
	Count int `json:"count"`
}

func (d *RemoveDomainCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	if d.Force && d.DryRun {
		return fmt.Errorf("--force and --dry-run flags cannot be used together")
	}
	ctx, cancel := createCancellableContext()
	defer cancel()
	var countResponse CountResponse
	var apiErr huma.ErrorModel

	err := requestWithSpinner(
		ctx,
		"Calculating number of associated domains...",
		func() *requests.Builder {
			return requests.
				URL(g.ServerURL + "/api/domains/" + d.DomainID + "/impact").
				Method(http.MethodGet).
				ToJSON(&countResponse).
				ErrorJSON(&apiErr)
		},
	)
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
		return HandleRequestError(err, g.ServerURL)
	}

	if !d.Force {
		_, _ = fmt.Fprintf(
			os.Stderr,
			"This operation will delete %d domain(s) and all associated records.\n",
			countResponse.Count,
		)
		if d.DryRun {
			return nil
		}
		_, _ = fmt.Fprint(os.Stderr, "Are you sure? [y/N]")
		var answer string
		_, _ = fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			_, _ = fmt.Fprint(os.Stderr, "Delete cancelled.")
			return nil
		}
	}

	err = requestWithSpinner(ctx, "Removing domains...", func() *requests.Builder {
		return requests.
			URL(g.ServerURL + "/api/domains/" + d.DomainID).
			Method(http.MethodDelete).
			ErrorJSON(&apiErr)
	})
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
		return HandleRequestError(err, g.ServerURL)
	}

	if g.Format == "json" {
		result := map[string]any{
			"status":    "success",
			"message":   "Domain deleted successfully",
			"domain_id": d.DomainID,
			"deleted":   countResponse.Count,
		}
		jsonOutput, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(jsonOutput))
	} else {
		fmt.Printf("Successfully deleted domain with ID: %s\n", d.DomainID)
	}
	return nil
}

type ListDomainCmd struct {
	Search   string `help:"Domain search term" example:"tesla.com" default:""`
	Page     int    `help:"Page number to retrieve" default:"1"`
	PageSize int    `help:"Number of items per page" default:"20"`
}

func (d *ListDomainCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()

	var apiErr huma.ErrorModel
	var domains struct {
		Domains    []dto.Domain              `json:"domains"`
		Pagination server.PaginationMetadata `json:"pagination"`
	}
	err := requestWithSpinner(ctx, "Listing domains...", func() *requests.Builder {
		return requests.
			URL(g.ServerURL+"/api/domains").
			Param("page", fmt.Sprintf("%d", d.Page)).
			Param("page_size", fmt.Sprintf("%d", d.PageSize)).
			Param("name", d.Search).
			ToJSON(&domains).
			ErrorJSON(&apiErr)
	})
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
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
		totalPages := (int32(domains.Pagination.Total) + int32(d.PageSize) - 1) / int32(d.PageSize)
		fmt.Printf("\n--- Page %d of %d (Total items: %d) ---\n",
			domains.Pagination.Page,
			totalPages,
			domains.Pagination.Total)

		// Show how to get next page
		if domains.Pagination.Page < totalPages {
			fmt.Printf("For next page: gecko domain list --page=%d --page-size=%d\n",
				d.Page+1, d.PageSize)
		}
	}

	return nil
}

type DomainRecordsCmd struct {
	DomainID string `arg:"" required:"" help:"Domain ID to fetch records for" example:"domain_00000001"`
	QType    string `help:"Comma separated list of record types. Defaults to all." default:""`
}

func (d *DomainRecordsCmd) Run(g *Globals, dc *DomainCmd) error {
	if err := ValidateStartup(g); err != nil {
		return err
	}
	ctx, cancel := createCancellableContext()
	defer cancel()

	var apiErr huma.ErrorModel
	var recordsResp struct {
		Pagination *server.PaginationMetadata `json:"pagination"`
		Records    dto.AllRecords             `json:"records"`
	}

	err := requestWithSpinner(
		ctx,
		"Fetching domain records...",
		func() *requests.Builder {
			return requests.
				URL(g.ServerURL+"/api/domains/"+d.DomainID+"/records").
				Param("qtype", d.QType).
				ToJSON(&recordsResp).
				ErrorJSON(&apiErr)
		},
	)
	if err != nil {
		if apiErr.Status != 0 {
			return handleHumaError(apiErr)
		}
		return HandleRequestError(err, g.ServerURL)
	}

	if g.Format == "json" {
		fmt.Println(formatOutput(recordsResp, g.Format))
	} else {
		// Domain header
		fmt.Printf("Domain: %s\n\n", recordsResp.Records.DomainName)

		// Print tables for each record type that has records
		printARecordsTable(recordsResp.Records.A)
		printAAAARecordsTable(recordsResp.Records.AAAA)
		printMXRecordsTable(recordsResp.Records.MX)
		printTXTRecordsTable(recordsResp.Records.TXT)
		printNSRecordsTable(recordsResp.Records.NS)
		printCNAMERecordsTable(recordsResp.Records.CNAME)
		printSOARecordsTable(recordsResp.Records.SOA)
		printPTRRecordsTable(recordsResp.Records.PTR)
		printSRVRecordsTable(recordsResp.Records.SRV)
		printCAARecordsTable(recordsResp.Records.CAA)
		printDNSKEYRecordsTable(recordsResp.Records.DNSKEY)
		printDSRecordsTable(recordsResp.Records.DS)
		printRRSIGRecordsTable(recordsResp.Records.RRSIG)

		// Summary
		fmt.Println("\n---")
		fmt.Printf("Total Records: %d\n", recordsResp.Pagination.Total)
	}

	return nil
}
