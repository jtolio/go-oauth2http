// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2http

import (
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/golang/oauth2"
	"github.com/gorilla/sessions"
	"github.com/jtolds/go-oauth2http/utils"
)

func init() {
	gob.Register(&oauth2.Token{})
}

// ProviderHandler is an http.Handler that keeps track of authentication for
// a single OAuth2 provider
//
// ProviderHandler handles requests to the following paths:
//  * /login
//  * /logout
//  * /_cb
//
// ProviderHandler will also return associated state to you about its state,
// in addition to a LoginRequired middleware and a Login URL generator.
type ProviderHandler struct {
	provider         *Provider
	store            SessionGetter
	handler_base_url string
	urls             RedirectURLs
	http.Handler
}

// NewProviderHandler makes a provider handler. Requres a provider
// configuration, a session store, a base URL for the handler, and a
// collection of URLs for redirecting.
func NewProviderHandler(provider *Provider, store SessionGetter,
	handler_base_url string, urls RedirectURLs) *ProviderHandler {
	if urls.DefaultLoginURL == "" {
		urls.DefaultLoginURL = "/"
	}
	if urls.DefaultLogoutURL == "" {
		urls.DefaultLogoutURL = "/"
	}
	h := &ProviderHandler{
		provider:         provider,
		store:            store,
		handler_base_url: strings.TrimRight(handler_base_url, "/"),
		urls:             urls}
	h.Handler = utils.DirMux{
		"login":  utils.ExactHandler(http.HandlerFunc(h.login)),
		"logout": utils.ExactHandler(http.HandlerFunc(h.logout)),
		"_cb":    utils.ExactHandler(http.HandlerFunc(h.cb))}
	return h
}

// Token returns a token if the provider is currently logged in, or nil if not.
func (o *ProviderHandler) Token(r *http.Request) (*oauth2.Token, error) {
	session, err := o.store(r)
	if err != nil {
		return nil, err
	}
	return o.token(session), nil
}

// LoggedIn returns true if the user is logged in with this provider
func (o *ProviderHandler) LoggedIn(r *http.Request) (bool, error) {
	t, err := o.Token(r)
	return t != nil, err
}

func (o *ProviderHandler) token(session *sessions.Session) *oauth2.Token {
	val, exists := session.Values["token"]
	token, correct := val.(*oauth2.Token)
	if exists && correct && !token.Expired() {
		return token
	}
	return nil
}

// Logout prepares the request to log the user out of just this OAuth2
// provider. If you're using a ProviderGroup you may be interested in
// LogoutAll.
func (o *ProviderHandler) Logout(w http.ResponseWriter, r *http.Request) error {
	session, err := o.store(r)
	if err != nil {
		return err
	}
	delete(session.Values, "token")
	return session.Save(r, w)
}

// LoginURL returns the login URL for this provider
// redirect_to is the URL to navigate to after logging in, and force_prompt
// tells OAuth2 whether or not the login prompt should always be shown
// regardless of if the user is already logged in.
func (o *ProviderHandler) LoginURL(redirect_to string,
	force_prompt bool) string {
	return o.handler_base_url + "/login?" + url.Values{
		"redirect_to":  {redirect_to},
		"force_prompt": {fmt.Sprint(force_prompt)}}.Encode()
}

// LogoutURL returns the logout URL for this provider
// redirect_to is the URL to navigate to after logging out.
func (o *ProviderHandler) LogoutURL(redirect_to string) string {
	return o.handler_base_url + "/logout?" + url.Values{
		"redirect_to": {redirect_to}}.Encode()
}

func (o *ProviderHandler) login(w http.ResponseWriter, r *http.Request) {
	session, err := o.store(r)
	if err != nil {
		o.urls.handleError(w, r, 500, "session storage error", err)
		return
	}

	redirect_to := r.FormValue("redirect_to")
	if redirect_to == "" {
		redirect_to = o.urls.DefaultLoginURL
	}

	force_prompt, err := strconv.ParseBool(r.FormValue("force_prompt"))
	if err != nil {
		force_prompt = false
	}

	if !force_prompt && o.token(session) != nil {
		http.Redirect(w, r, redirect_to, http.StatusTemporaryRedirect)
		return
	}

	state := newState()
	session.Values["state"] = state
	session.Values["redirect_to"] = redirect_to
	err = session.Save(r, w)
	if err != nil {
		o.urls.handleError(w, r, 500, "session storage error", err)
		return
	}

	approval_prompt := "auto"
	if force_prompt {
		approval_prompt = "force"
	}

	http.Redirect(w, r, o.provider.AuthCodeURL(state, "online", approval_prompt),
		http.StatusTemporaryRedirect)
}

func (o *ProviderHandler) cb(w http.ResponseWriter, r *http.Request) {
	session, err := o.store(r)
	if err != nil {
		o.urls.handleError(w, r, 500, "session storage error", err)
		return
	}

	val, exists := session.Values["state"]
	existing_state, correct := val.(string)
	if !exists || !correct {
		o.urls.handleError(w, r, 500, "session storage error",
			fmt.Errorf("invalid state"))
		return
	}

	val, exists = session.Values["redirect_to"]
	redirect_to, correct := val.(string)
	if !exists || !correct {
		o.urls.handleError(w, r, 500, "session storage error",
			fmt.Errorf("invalid redirect_to"))
		return
	}

	if existing_state != r.FormValue("state") {
		o.urls.handleError(w, r, 400, "csrf detected", fmt.Errorf("csrf detected"))
		return
	}

	token, err := o.provider.Exchange(r.FormValue("code"))
	if err != nil {
		o.urls.handleError(w, r, 500, "oauth error",
			fmt.Errorf("transport error: %s", err))
		return
	}

	session.Values["token"] = token
	err = session.Save(r, w)
	if err != nil {
		o.urls.handleError(w, r, 500, "session storage error", err)
		return
	}

	http.Redirect(w, r, redirect_to, http.StatusTemporaryRedirect)
}

func (o *ProviderHandler) logout(w http.ResponseWriter, r *http.Request) {
	err := o.Logout(w, r)
	if err != nil {
		o.urls.handleError(w, r, 500, "session storage error", err)
		return
	}
	redirect_to := r.FormValue("redirect_to")
	if redirect_to == "" {
		redirect_to = o.urls.DefaultLogoutURL
	}
	http.Redirect(w, r, redirect_to, http.StatusTemporaryRedirect)
}

// LoginRequired is a middleware for redirecting users to a login page if
// they aren't logged in yet. If you are using a ProviderGroup and don't know
// which provider a user should use, consider using
// (*ProviderGroup).LoginRequired instead
func (o *ProviderHandler) LoginRequired(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := o.Token(r)
		if err != nil {
			o.urls.handleError(w, r, 500, "session storage error", err)
			return
		}
		if token != nil {
			h.ServeHTTP(w, r)
		} else {
			http.Redirect(w, r, o.LoginURL(r.RequestURI, false),
				http.StatusTemporaryRedirect)
		}
	})
}
