package ui

import "embed"

//go:embed templates/*.html static/* images/* site.webmanifest
var Assets embed.FS
