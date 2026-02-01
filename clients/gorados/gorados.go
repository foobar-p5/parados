package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// library item
type item struct {
	ID   string    `json:"id"`
	Path string    `json:"path"`
}

// upstream response
type library_resp struct {
	Proto int      `json:"proto"`
	Items []item   `json:"items"`
}

// app state
type handler struct {
	parados        string
	user           string
	pass           string
	httpc*         http.Client
}

func (h* handler) library(w http.ResponseWriter, r *http.Request) {
	// build upstream req
	req, _ := http.NewRequest("GET", h.parados+"/library", nil)
	if h.user != "" {
		req.SetBasicAuth(h.user, h.pass)
	}

	// call upstream
	resp, err := h.httpc.Do(req)
	if err != nil {
		http.Error(w, "Upstream Error", 502)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		http.Error(w, resp.Status, resp.StatusCode)
		return
	}

	// decode json
	var lr library_resp
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		http.Error(w, "Bad JSON", 502)
		return
	}
	if lr.Proto != 1 {
		http.Error(w, "Unknown Proto Version", 502)
		return
	}

	// tmp html
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>parados</title>")
	fmt.Fprintf(w, "<h1>parados</h1><p>items: %d</p><ul>", len(lr.Items))
	for _, it := range lr.Items {
		fmt.Fprintf(w, `<li><a href="/item/%s">%s</a></li>`, it.ID, it.Path)
	}
	fmt.Fprintf(w, "</ul>")
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8808", "Listen Addr")
	par := flag.String("parados", "http://127.0.0.1:8088", "Parados Base URL")
	flag.Parse()

	user := "admin"
	pass := "123"

	h := &handler{
		parados: *par,
		user:    user,
		pass:    pass,
		httpc:   &http.Client{Timeout: 15 * time.Second},
	}

	// routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/library", http.StatusSeeOther)
	})
	mux.HandleFunc("/library", h.library)

	// start server
	fmt.Fprintf(os.Stderr, "gorados: listening on %s\n", *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

