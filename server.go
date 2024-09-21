package main

import (
	"github.com/pkg/sftp"
	"log/slog"
	"net/http"
)

func getStaticHandler(prefix string, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// remove prefix from path
		// look up the file in the go embed filesystem by path, setting content type headers by extension
	}
}

func serve(listenAddr string, client *sftp.Client, logger *slog.Logger) error {
	http.HandleFunc("/", getStaticHandler("/", logger))
	http.HandleFunc("/static/", getStaticHandler("/static/", logger))

	// TODO handle oAuth routes

	// TODO handle all other routes

	return http.ListenAndServe(listenAddr, nil)
}
