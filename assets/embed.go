package assets

import "embed"

//go:embed "migrations" "files"
var EmbeddedAssets embed.FS
