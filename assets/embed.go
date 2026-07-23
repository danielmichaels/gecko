package assets

import "embed"

//go:embed "migrations" "files" "static" "seeds"
var EmbeddedAssets embed.FS
