package assets

import "embed"

//go:embed "migrations" "files" "static"
var EmbeddedAssets embed.FS
