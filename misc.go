// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2http

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

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
