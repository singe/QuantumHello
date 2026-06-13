package ui

import "embed"

//go:embed templates/*.html static/* images/*
var Assets embed.FS
