// gorados
// is a Go frontend for the parados
// HTTP media server

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// library item
type item struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}

// upstream response
type library_resp struct {
	Proto int    `json:"proto"`
	Items []item `json:"items"`
}

// /meta/{id} response
type meta_resp struct {
	Proto int    `json:"proto"`
	ID    string `json:"id"`
	Path  string `json:"path"`
	Name  string `json:"name"`
	Size  uint64 `json:"size"`
	Mtime int64  `json:"mtime"`
	Type  string `json:"type"`
	Kind  string `json:"kind"`
}

// app state
type handler struct {
	parados string
	user    string
	pass    string
	httpc   *http.Client
}

func (h *handler) get_json(url string, out any) (int, error) {
	req, _ := http.NewRequest("GET", url, nil)
	if h.user != "" {
		req.SetBasicAuth(h.user, h.pass)
	}

	resp, err := h.httpc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return resp.StatusCode, nil
	}

	return 200, json.NewDecoder(resp.Body).Decode(out)
}

func (h *handler) library(w http.ResponseWriter, r *http.Request) {
	var lr library_resp
	code, err := h.get_json(h.parados+"/library", &lr)
	if err != nil {
		http.Error(w, "Upstream Error", 502)
		return
	}
	if code != 200 {
		http.Error(w, http.StatusText(code), code)
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

func (h *handler) item(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/item/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	var mr meta_resp
	code, err := h.get_json(h.parados+"/meta/"+id, &mr)
	if err != nil {
		http.Error(w, "Upstream Error", 502)
		return
	}
	if code != 200 {
		http.Error(w, http.StatusText(code), code)
		return
	}
	if mr.Proto != 1 {
		http.Error(w, "Unknown Proto Version", 502)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>%s</title>", mr.Name)
	fmt.Fprintf(w, "<h1>%s</h1>", mr.Name)
	fmt.Fprintf(w, "<p><code>%s</code></p>", mr.Path)
	fmt.Fprintf(w, "<ul>")
	fmt.Fprintf(w, "<li>id: <code>%s</code></li>", mr.ID)
	fmt.Fprintf(w, "<li>type: <code>%s</code></li>", mr.Type)
	fmt.Fprintf(w, "<li>kind: <code>%s</code></li>", mr.Kind)
	fmt.Fprintf(w, "<li>size: %d</li>", mr.Size)
	fmt.Fprintf(w, "<li>mtime: %d</li>", mr.Mtime)
	fmt.Fprintf(w, "</ul>")

	// player
	if mr.Kind == "video" {
		fmt.Fprintf(w, `<video controls preload="metadata" style="max-width: 100%%;" src="/stream/%s"></video>`, mr.ID)

	} else if mr.Kind == "audio" {
		fmt.Fprintf(w, `<audio controls preload="metadata" style="width: 100%%;" src="/stream/%s"></audio>`, mr.ID)

	} else if mr.Kind == "image" {
		fmt.Fprintf(w, `<p><img style="max-width: 100%%;" src="/stream/%s"></p>`, mr.ID)

	} else {
		fmt.Fprintf(w, `<p><a href="/stream/%s">download</a></p>`, mr.ID)
	}

	fmt.Fprintf(w, `<p><a href="/library">back</a> | <a href="/stream/%s">stream</a></p>`, mr.ID)
}

func (h *handler) stream(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/stream/")
	if id == "" {
		http.NotFound(w, r)
		return
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		http.Error(w, "Method Not Allowed", 405)
		return
	}

	// build upstream req
	req, _ := http.NewRequest(r.Method, h.parados+"/stream/"+id, nil)
	if h.user != "" {
		req.SetBasicAuth(h.user, h.pass)
	}

	// pass through Range for seeking
	rng := r.Header.Get("Range")
	if rng != "" {
		req.Header.Set("Range", rng)
	}

	// call upstream
	resp, err := h.httpc.Do(req)
	if err != nil {
		http.Error(w, "Upstream Error", 502)
		return
	}
	defer resp.Body.Close()

	// copy important headers for playback
	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	cl := resp.Header.Get("Content-Length")
	if cl != "" {
		w.Header().Set("Content-Length", cl)
	}

	cr := resp.Header.Get("Content-Range")
	if cr != "" {
		w.Header().Set("Content-Range", cr)
	}

	ar := resp.Header.Get("Accept-Ranges")
	if ar != "" {
		w.Header().Set("Accept-Ranges", ar)
	}

	cd := resp.Header.Get("Content-Disposition")
	if cd != "" {
		w.Header().Set("Content-Disposition", cd)
	}

	// mirror status (200/206/400/416/401/404/etc)
	w.WriteHeader(resp.StatusCode)

	// HEAD: no body
	if r.Method == "HEAD" {
		return
	}

	// stream body
	io.Copy(w, resp.Body)
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
	mux.HandleFunc("/item/", h.item)
	mux.HandleFunc("/stream/", h.stream)

	// start server
	fmt.Fprintf(os.Stderr, "gorados: listening on %s\n", *listen)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

