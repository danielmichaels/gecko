package assessor

import "strings"

// cnameFingerprint maps a CNAME target suffix to the third-party service that
// serves it. TakeoverPossible marks providers where an unclaimed resource can be
// registered by an attacker (the subdomain-takeover risk); ErrorBody is the
// response-body marker the HTTP prober looks for to confirm the resource is
// actually unclaimed, used to separate a real takeover candidate from a live site.
type cnameFingerprint struct {
	Suffix           string
	Provider         string
	ErrorBody        string
	TakeoverPossible bool
}

// cnameFingerprints is a deliberately small, high-confidence catalogue seeded from
// the well-known can-i-take-over-xyz entries. It is hand-maintained rather than
// vendored: the long tail of providers needs per-provider HTTP body matching to be
// meaningful, so we only carry entries we can act on conservatively.
var cnameFingerprints = []cnameFingerprint{
	{
		Suffix:           ".s3.amazonaws.com",
		Provider:         "AWS S3",
		ErrorBody:        "NoSuchBucket",
		TakeoverPossible: true,
	},
	{Suffix: ".s3-website", Provider: "AWS S3", ErrorBody: "NoSuchBucket", TakeoverPossible: true},
	{
		Suffix:           ".github.io",
		Provider:         "GitHub Pages",
		ErrorBody:        "There isn't a GitHub Pages site here.",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".herokuapp.com",
		Provider:         "Heroku",
		ErrorBody:        "No such app",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".herokudns.com",
		Provider:         "Heroku",
		ErrorBody:        "No such app",
		TakeoverPossible: true,
	},
	{Suffix: ".cloudapp.net", Provider: "Microsoft Azure", ErrorBody: "", TakeoverPossible: true},
	{
		Suffix:           ".cloudapp.azure.com",
		Provider:         "Microsoft Azure",
		ErrorBody:        "",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".azurewebsites.net",
		Provider:         "Microsoft Azure",
		ErrorBody:        "",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".trafficmanager.net",
		Provider:         "Microsoft Azure",
		ErrorBody:        "",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".blob.core.windows.net",
		Provider:         "Microsoft Azure",
		ErrorBody:        "",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".fastly.net",
		Provider:         "Fastly",
		ErrorBody:        "Fastly error: unknown domain",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".surge.sh",
		Provider:         "Surge.sh",
		ErrorBody:        "project not found",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".bitbucket.io",
		Provider:         "Bitbucket",
		ErrorBody:        "Repository not found",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".pantheonsite.io",
		Provider:         "Pantheon",
		ErrorBody:        "The gods are wise, but do not know of the site which you seek.",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".ghost.io",
		Provider:         "Ghost",
		ErrorBody:        "The thing you were looking for is no longer here, or never was",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".domains.tumblr.com",
		Provider:         "Tumblr",
		ErrorBody:        "Whatever you were looking for doesn't currently exist at this address.",
		TakeoverPossible: true,
	},
	{
		Suffix:           ".myshopify.com",
		Provider:         "Shopify",
		ErrorBody:        "Sorry, this shop is currently unavailable.",
		TakeoverPossible: false,
	},
	{
		Suffix:           ".zendesk.com",
		Provider:         "Zendesk",
		ErrorBody:        "Help Center Closed",
		TakeoverPossible: false,
	},
}

// matchFingerprint returns the first catalogue entry whose suffix the CNAME target
// ends with, after normalising case and any trailing dot. The catalogue is small
// enough that a linear scan is the simplest correct approach.
func matchFingerprint(target string) (cnameFingerprint, bool) {
	normalized := strings.ToLower(strings.TrimSuffix(target, "."))
	for _, fp := range cnameFingerprints {
		if strings.Contains(normalized, fp.Suffix) {
			return fp, true
		}
	}
	return cnameFingerprint{}, false
}
