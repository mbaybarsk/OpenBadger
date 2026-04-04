package migrations

import "embed"

// Files contains the embedded SQL migrations used by the migrate mode.
//
//go:embed *.sql
var Files embed.FS
