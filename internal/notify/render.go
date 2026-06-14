package notify

import (
	"fmt"
	"html"
	"strings"
	"time"
)

// DigestSummary is the tenant-wide change rollup for one digest window.
type DigestSummary struct {
	Breakdown  []BreakdownItem
	Created    int
	Updated    int
	Deleted    int
	HighImpact int
}

// Total is the count of changes in the window across all change types.
func (s DigestSummary) Total() int { return s.Created + s.Updated + s.Deleted }

// BreakdownItem is one (entity_type, change_type) tally in the digest.
type BreakdownItem struct {
	EntityType string
	ChangeType string
	Count      int
}

// HighImpactItem is one critical/high-severity change surfaced in the digest body.
type HighImpactItem struct {
	ObservedAt time.Time
	DomainName string
	EntityType string
	ChangeType string
	Severity   string
	Status     string
}

// RenderDailyDigest builds the channel-agnostic Notification for a tenant's daily
// digest: a summary line, the per-entity breakdown, and (when present) an itemized
// high-impact section. Links use the trusted baseURL (config PublicBaseURL), never a
// request-derived origin. Mirrors the inline HTML+text approach in service/auth.go;
// kept here as the single render boundary so the worker stays thin.
func RenderDailyDigest(
	tenantName, baseURL string,
	s DigestSummary,
	highImpact []HighImpactItem,
) Notification {
	subject := fmt.Sprintf("gecko: %d DNS change%s detected", s.Total(), plural(s.Total()))
	if s.HighImpact > 0 {
		subject = fmt.Sprintf(
			"gecko: %d high-impact + %d DNS change%s detected",
			s.HighImpact, s.Total(), plural(s.Total()),
		)
	}

	link := baseURL + "/app/domains"

	var htmlB, textB strings.Builder

	htmlB.WriteString(
		"<p>Here's what changed across <b>" + html.EscapeString(
			tenantName,
		) + "</b> since your last digest.</p>",
	)
	fmt.Fprintf(
		&htmlB,
		"<p><b>%d</b> created, <b>%d</b> updated, <b>%d</b> deleted.</p>",
		s.Created, s.Updated, s.Deleted,
	)

	textB.WriteString("What changed across " + tenantName + " since your last digest.\n\n")
	fmt.Fprintf(
		&textB,
		"%d created, %d updated, %d deleted.\n", s.Created, s.Updated, s.Deleted,
	)

	if s.HighImpact > 0 {
		fmt.Fprintf(
			&htmlB,
			"<h3>%d high-impact change%s</h3><ul>", s.HighImpact, plural(s.HighImpact),
		)
		fmt.Fprintf(
			&textB,
			"\nHigh-impact changes (%d):\n", s.HighImpact,
		)
		for _, hi := range highImpact {
			line := fmt.Sprintf(
				"%s — %s %s (%s)",
				hi.DomainName, hi.ChangeType, humanizeEntity(hi.EntityType), hi.Severity,
			)
			htmlB.WriteString("<li>" + html.EscapeString(line) + "</li>")
			textB.WriteString("  - " + line + "\n")
		}
		htmlB.WriteString("</ul>")
	}

	if len(s.Breakdown) > 0 {
		htmlB.WriteString("<h3>By record type</h3><ul>")
		textB.WriteString("\nBy record type:\n")
		for _, b := range s.Breakdown {
			line := fmt.Sprintf(
				"%s %s: %d", humanizeEntity(b.EntityType), b.ChangeType, b.Count,
			)
			htmlB.WriteString("<li>" + html.EscapeString(line) + "</li>")
			textB.WriteString("  - " + line + "\n")
		}
		htmlB.WriteString("</ul>")
	}

	htmlB.WriteString("<p><a href=\"" + html.EscapeString(link) + "\">Open your dashboard</a></p>")
	textB.WriteString("\nOpen your dashboard: " + link + "\n")

	return Notification{
		TenantID: 0,
		Kind:     KindDailyDigest,
		Subject:  subject,
		HTML:     htmlB.String(),
		Text:     textB.String(),
	}
}

// RenderHighImpactAlert builds the channel-agnostic Notification for a near-real-time
// high-impact alert: an itemized list of the critical/high findings detected in the
// sweep window. It is a separate, terser message from the daily digest (Kind
// distinguishes them) so an immediate alert reads as urgent, not as a summary.
func RenderHighImpactAlert(
	tenantName, baseURL string,
	items []HighImpactItem,
) Notification {
	subject := fmt.Sprintf(
		"gecko: %d high-impact DNS finding%s detected", len(items), plural(len(items)),
	)
	link := baseURL + "/app/findings"

	var htmlB, textB strings.Builder
	htmlB.WriteString(
		"<p>New high-impact finding" + plural(len(items)) + " on <b>" +
			html.EscapeString(tenantName) + "</b>:</p><ul>",
	)
	textB.WriteString("New high-impact findings on " + tenantName + ":\n\n")
	for _, hi := range items {
		line := fmt.Sprintf(
			"%s — %s %s (%s)",
			hi.DomainName, hi.ChangeType, humanizeEntity(hi.EntityType), hi.Severity,
		)
		htmlB.WriteString("<li>" + html.EscapeString(line) + "</li>")
		textB.WriteString("  - " + line + "\n")
	}
	htmlB.WriteString("</ul>")
	htmlB.WriteString("<p><a href=\"" + html.EscapeString(link) + "\">Review findings</a></p>")
	textB.WriteString("\nReview findings: " + link + "\n")

	return Notification{
		TenantID: 0,
		Kind:     KindHighImpact,
		Subject:  subject,
		HTML:     htmlB.String(),
		Text:     textB.String(),
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// humanizeEntity turns an observation entity_type (e.g. "a_record",
// "dangling_cname_finding") into a friendlier label ("a record", "dangling cname
// finding") for the email body.
func humanizeEntity(entityType string) string {
	return strings.ReplaceAll(entityType, "_", " ")
}
