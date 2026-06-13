package app

import (
	"io/fs"
	"net/http"

	"quantumhello/internal/ui"
)

func staticFS() http.FileSystem {
	return assetFS("static")
}

func imagesFS() http.FileSystem {
	return assetFS("images")
}

func assetFS(dir string) http.FileSystem {
	sub, err := fs.Sub(ui.Assets, dir)
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
