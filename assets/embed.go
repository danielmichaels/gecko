package assets

import "embed"

//go:embed "migrations"
var EmbeddedAssets embed.FS
