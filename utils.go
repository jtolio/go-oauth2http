// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2http

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/spacemonkeygo/spacelog"
)

var (
	logger = spacelog.GetLogger()
)

// RedirectURLs contains a collection of URLs to redirect to in a variety
// of cases
type RedirectURLs struct {
	// ErrorURL should return a URL for an error given an HTTP status code
	// and an error message
	ErrorURL func(code int, msg string) string

	// If a login URL isn't provided to redirect to after successful login, use
	// this one.
	DefaultLoginURL string

	// If a logout URL isn't provided to redirect to after successful logout, use
	// this one.
	DefaultLogoutURL string
}

func (u RedirectURLs) handleError(w http.ResponseWriter, r *http.Request,
	code int, msg string, err error) {
	logger.Errorf("[%d] %s: %s", code, msg, err)
	if u.ErrorURL == nil {
		http.Error(w, msg, code)
		return
	}
	url := u.ErrorURL(code, msg)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

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

func newState() string {
	var p [16]byte
	_, err := rand.Read(p[:])
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(p[:])
}

type SessionGetter func(r *http.Request) (*sessions.Session, error)

// SessionFromStore returns a SessionGetter given a constant session store
// and a session namespace
func SessionFromStore(store sessions.Store,
	session_namespace string) SessionGetter {
	return SessionGetter(func(r *http.Request) (*sessions.Session, error) {
		return store.Get(r, session_namespace)
	})
}
