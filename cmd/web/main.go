package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"quantumhello/internal/app"
	"quantumhello/internal/probe"
)

func main() {
	var (
		addr  = flag.String("addr", ":8080", "listen address")
		check = flag.String("check", "", "check a host/URL and print JSON")
	)
	flag.Parse()

	checker := probe.NewChecker()

	if *check != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		result, err := checker.Check(ctx, *check, "127.0.0.1")
		if err != nil {
			log.Fatal(err)
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			log.Fatal(err)
		}
		return
	}

	srv, err := app.NewServer(checker)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on %s", *addr)
	log.Fatal(server.ListenAndServe())
}
