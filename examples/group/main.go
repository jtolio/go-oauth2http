// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

// This example shows how to set up a web service that allows users to log in
// via multiple OAuth2 providers
package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"

	"github.com/golang/oauth2"
	"github.com/gorilla/context"
	"github.com/gorilla/sessions"
	"github.com/jtolds/go-oauth2http"
	"github.com/jtolds/go-oauth2http/utils"
	"github.com/spacemonkeygo/flagfile"
	"github.com/spacemonkeygo/monitor"
	"github.com/spacemonkeygo/spacelog"
	"github.com/spacemonkeygo/spacelog/setup"
)

var (
	listenAddr = flag.String("addr", ":8080", "address to listen on")
	debugAddr  = flag.String("debug_addr", "localhost:0",
		"address to listen on for debugging")
	publicAddr = flag.String("public_addr", "localhost:8080",
		"public address for URLs")
	cookieSecret = flag.String("cookie_secret", "secret",
		"the secret for securing cookie information")

	logger = spacelog.GetLogger()
)

type SampleHandler struct {
	Group      *oauth2http.ProviderGroup
	Restricted bool
}

func (s *SampleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.Group.Tokens(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	if s.Restricted {
		fmt.Fprintf(w, `<h3>Restricted</h3>`)
	}
	if len(tokens) > 0 {
		fmt.Fprintf(w, `
	    <p>Logged in with:
      	<ul>
  	`)
		for name := range tokens {
			fmt.Fprintf(w, `
		    <li>%s (<a href="%s">logout</a>)</li>
	    `, name, s.Group.LogoutURL(name, "/"))
		}
		fmt.Fprintf(w, `
		    <li><a href="%s">logout all</a></li>
	    `, s.Group.LogoutAllURL("/"))
		fmt.Fprintf(w, `
		  </ul></p>`)
	} else {
		fmt.Fprintf(w, `
	    <p>Not logged in</p>
    `)
	}

	login_possible := false
	for name := range s.Group.Providers() {
		_, logged_in := tokens[name]
		if !logged_in {
			login_possible = true
			break
		}
	}

	if login_possible {
		fmt.Fprintf(w, "<p>Log in with:<ul>")
	}
	for name, provider := range s.Group.Providers() {
		_, logged_in := tokens[name]
		if logged_in {
			continue
		}
		fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`,
			provider.LoginURL(r.RequestURI, false), name)
	}
	fmt.Fprintf(w, "</ul></p>")

	if !s.Restricted {
		fmt.Fprintf(w, `
	    <p><a href="/restricted">Restricted</a></p>
    `)
	}
}

type LoginHandler struct {
	Group *oauth2http.ProviderGroup
}

func (l *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<h3>Login required</h3>`)
	fmt.Fprintf(w, "<p>Log in with:<ul>")
	for name, provider := range l.Group.Providers() {
		fmt.Fprintf(w, `<li><a href="%s">%s</a></li>`,
			provider.LoginURL(r.FormValue("redirect_to"), false), name)
	}
	fmt.Fprintf(w, "</ul></p>")
}

func loginurl(redirect_to string) string {
	return "/login?" + url.Values{"redirect_to": {redirect_to}}.Encode()
}

func main() {
	flagfile.Load()
	setup.MustSetup("example")
	monitor.RegisterEnvironment()
	go http.ListenAndServe(*debugAddr, monitor.DefaultStore)

	store := sessions.NewCookieStore([]byte(*cookieSecret))

	group, err := oauth2http.NewProviderGroup(
		store, "oauth", "/auth", oauth2http.RedirectURLs{},
		oauth2http.Github(&oauth2.Options{
			ClientID:     "<client_id>",
			ClientSecret: "<client_secret>"}),
		oauth2http.Facebook(&oauth2.Options{
			ClientID:     "<client_id>",
			ClientSecret: "<client_secret>",
			RedirectURL:  "http://localhost:8080/auth/facebook/_cb"}))
	if err != nil {
		panic(err)
	}

	logger.Notice("listening")

	http.ListenAndServe(*listenAddr,
		utils.LoggingHandler(context.ClearHandler(
			utils.DirMux{
				"":      &SampleHandler{Group: group, Restricted: false},
				"login": &LoginHandler{Group: group},
				"logout": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Redirect(w, r, "/auth/all/logout", http.StatusTemporaryRedirect)
				}),
				"restricted": group.LoginRequired(
					&SampleHandler{Group: group, Restricted: true}, loginurl),
				"auth": group})))
}
