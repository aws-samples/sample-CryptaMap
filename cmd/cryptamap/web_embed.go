package main

import "embed"

// webDist is the staged dashboard Single-Page-App bundle, embedded into the
// binary so `cryptamap serve` ships the UI with zero filesystem dependency.
//
// The committed contents are a PLACEHOLDER index.html only — the real Vite
// build output lives in dashboard/dist, which is OUTSIDE cmd/cryptamap, and
// go:embed cannot reach across directories. `make build-serve` builds the
// dashboard and copies dashboard/dist/* into cmd/cryptamap/webdist BEFORE
// `go build`, so the released binary embeds the real SPA; a plain `go build`
// still compiles because the placeholder keeps the directory non-empty.
//
// `all:` includes files whose names begin with `_` or `.` (Vite emits hashed
// assets under assets/ and may emit dotfiles), so nothing is silently dropped.
//
//go:embed all:webdist
var webDist embed.FS
