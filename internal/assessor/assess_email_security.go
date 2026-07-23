package assessor

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/danielmichaels/gecko/internal/store"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	// MinDKIMKeyLength is the minimum allowed DKIM key length
	MinDKIMKeyLength = 270
	// MaxSPFLookups is the maximum allowed SPF include mechanisms
	MaxSPFLookups = 10
)

var (
	SPFPrefix          = regexp.MustCompile(`^v=(?i)spf1`)
	knownDkimSelectors = []string{
		"x",             // Generic
		"google",        // Google
		"selector1",     // Microsoft
		"selector2",     // Microsoft
		"s1",            // Generic
		"s2",            // Generic
		"k1",            // MailChimp
		"mandrill",      // Mandrill
		"everlytickey1", // Everlytic
		"everlytickey2", // Everlytic
		"dkim",          // Hetzner
		"mxvault",       // MxVault
	}
)

// hasDeliverableMX reports whether the domain has at least one real MX target.
// A null-MX (RFC 7505: target ".") is an explicit "no mail" declaration and does
// not count.
func hasDeliverableMX(mxRecords []store.MxRecords) bool {
	for _, mx := range mxRecords {
		if strings.TrimSuffix(strings.TrimSpace(mx.Target), ".") != "" {
			return true
		}
	}
	return false
}

func (a *Assessor) AssessEmailSecurity(ctx context.Context, domainID int) error {
	domain, err := a.store.DomainsGetByIdentifier(ctx, store.DomainsGetByIdentifierParams{
		ID:       int32(domainID),
		TenantID: pgtype.Int4{Int32: a.identity.TenantID, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("get domain %d: %w", domainID, err)
	}

	ev, err := a.collectEmailSecurity(ctx, domain.ID, domain.Name)
	if err != nil {
		return err
	}
	res, err := detect.EmailSecurityDetector{
		MaxSPFLookups:    MaxSPFLookups,
		MinDKIMKeyLength: MinDKIMKeyLength,
		MTASTSMinMaxAge:  mtaStsMinMaxAge,
	}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.ID, domain.Name, detect.CheckEmailSecurity, res)
}

// collectEmailSecurity gathers evidence for all six email sub-checks: SPF from the
// stored apex TXT records; DKIM/DMARC via per-name 3-way TXT lookups (so SERVFAIL
// is not read as "absent"); BIMI/TLS-RPT via prefixed TXT lookups; MTA-STS via its
// TXT record plus the HTTPS policy fetch. The _dmarc lookup is done once and shared
// with BIMI's enforcement check.
func (a *Assessor) collectEmailSecurity(
	ctx context.Context,
	domainID int32,
	name string,
) (detect.EmailSecurityEvidence, error) {
	id := pgtype.Int4{Int32: domainID, Valid: true}
	mx, err := a.store.RecordsGetMXByDomainID(ctx, id)
	if err != nil {
		return detect.EmailSecurityEvidence{}, fmt.Errorf("get MX records: %w", err)
	}
	txt, err := a.store.RecordsGetTXTByDomainID(ctx, id)
	if err != nil {
		return detect.EmailSecurityEvidence{}, fmt.Errorf("get TXT records: %w", err)
	}

	ev := detect.EmailSecurityEvidence{HandlesEmail: hasDeliverableMX(mx)}
	for _, t := range txt {
		if SPFPrefix.MatchString(t.Value) {
			ev.SPFRecords = append(ev.SPFRecords, t.Value)
		}
	}
	for _, m := range mx {
		ev.MXTargets = append(ev.MXTargets, m.Target)
	}
	ev.DKIMSelectorsChecked = knownDkimSelectors

	// The five remaining sub-checks each hit the network and write disjoint
	// evidence fields, so run them concurrently (restoring the pre-refactor
	// errgroup fan-out). The DKIM selector loop is the long pole. _dmarc is still
	// looked up once here and shared with the detector's BIMI enforcement check.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		for _, selector := range knownDkimSelectors {
			recs, st := a.dnsClient.LookupWithStatus(
				fmt.Sprintf("%s._domainkey.%s", selector, name), dns.TypeTXT,
			)
			ev.DKIMSelectors = append(ev.DKIMSelectors, detect.DKIMSelectorEvidence{
				Selector: selector,
				Status:   resolutionString(st),
				Records:  recs,
			})
		}
		return nil
	})
	g.Go(func() error {
		dmarcRecs, dmarcSt := a.dnsClient.LookupWithStatus("_dmarc."+name, dns.TypeTXT)
		ev.DMARCStatus = resolutionString(dmarcSt)
		ev.DMARCRecords = dmarcRecs
		return nil
	})
	g.Go(func() error {
		ev.BIMIRecord = a.lookupBIMIRecord(name)
		return nil
	})
	g.Go(func() error {
		if a.lookupTXTPrefixed("_mta-sts."+name, "v=STSv1") != "" {
			ev.MTASTSConfigured = true
			res := a.prober.Get(gctx, "https://mta-sts."+name+"/.well-known/mta-sts.txt")
			ev.MTASTSPolicyReached = res.Reached
			ev.MTASTSPolicyStatus = res.StatusCode
			ev.MTASTSPolicyBody = res.Body
		}
		return nil
	})
	g.Go(func() error {
		ev.TLSRPTRecord = a.lookupTXTPrefixed("_smtp._tls."+name, "v=TLSRPTv1")
		return nil
	})
	if err := g.Wait(); err != nil {
		return detect.EmailSecurityEvidence{}, err
	}

	return ev, nil
}
