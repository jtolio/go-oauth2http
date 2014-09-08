// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package utils

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/spacemonkeygo/spacelog"
)

var (
	logger = spacelog.GetLogger()
)

// DirMux is an http.Handler that mimics a directory. It mutates an incoming
// requests URL.Path to properly namespace handlers. This way a handler can
// assume it has the root of its section. If you want the original URL use
// req.RequestURI (but don't modify it).
type DirMux map[string]http.Handler

func (d DirMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	dir, left := Shift(r.URL.Path)
	handler, ok := d[dir]
	if !ok {
		http.Error(w, fmt.Sprintf("not found: resource: %s", dir),
			http.StatusNotFound)
		return
	}
	r.URL.Path = left
	handler.ServeHTTP(w, r)
}

// Shift pulls the first directory out of the path and returns the remainder.
func Shift(path string) (dir, left string) {
	// slice off the first "/"s if they exists
	path = strings.TrimLeft(path, "/")

	if len(path) == 0 {
		return "", ""
	}

	// find the first '/' after the initial one
	split := strings.Index(path, "/")
	if split == -1 {
		return path, ""
	}
	return path[:split], path[split:]
}

// LoggingHandler is a simple middleware for logging requests
func LoggingHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Noticef("%s %s", r.Method, r.RequestURI)
		h.ServeHTTP(w, r)
	})
}

// ExactHandler returns a 404 if someone requests a subresource of the
// wrapped resource
func ExactHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dir, left := Shift(r.URL.Path)
		if dir != "" || left != "" {
			http.Error(w, fmt.Sprintf("not found: resource: %s", dir),
				http.StatusNotFound)
			return
		}
		h.ServeHTTP(w, r)
	})
}
