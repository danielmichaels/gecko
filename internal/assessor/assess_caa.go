package assessor

import (
	"context"
	"database/sql"
	"errors"

	"github.com/danielmichaels/gecko/internal/detect"
	"github.com/jackc/pgx/v5/pgtype"
)

// AssessCAA interprets the already-collected CAA records for a domain and
// records configuration-quality findings (missing/unrestricted/untrusted
// issuance, unknown critical flags, conflicting policy) plus standards
// compliance findings (CAA required for cert-bearing domains, missing iodef).
// It reads structured records from caa_records; no DNS egress occurs here.
func (a *Assessor) AssessCAA(ctx context.Context, domainUID string) error {
	domain, err := a.getDomain(ctx, domainUID)
	if err != nil {
		return err
	}

	records, err := a.store.RecordsGetCAAByDomainID(ctx, pgtype.Int4{Int32: domain.ID, Valid: true})
	if err != nil {
		a.logger.ErrorContext(
			ctx,
			"Failed to retrieve CAA records",
			"domain",
			domain.Uid,
			"error",
			err,
		)
		return err
	}

	ev := detect.CAAEvidence{LookedUp: true, HasCert: a.domainHasCertificate(ctx, domain.ID)}
	for _, r := range records {
		ev.Records = append(
			ev.Records,
			detect.CAARecord{Tag: r.Tag, Value: r.Value, Flags: r.Flags},
		)
	}
	res, err := detect.CAADetector{}.Detect(ev)
	if err != nil {
		return err
	}
	return a.reconcile(ctx, domain.ID, domain.Name, detect.CheckCAA, res)
}

func (a *Assessor) domainHasCertificate(ctx context.Context, domainID int32) bool {
	_, err := a.store.ScannersGetCertificate(ctx, pgtype.Int4{Int32: domainID, Valid: true})
	if err == nil {
		return true
	}
	if !errors.Is(err, sql.ErrNoRows) {
		a.logger.WarnContext(ctx, "failed to check certificate presence for CAA assessment",
			"domain_id", domainID, "error", err)
	}
	return false
}
