package main

import (
	"flag"
	"fmt"
	"net/http"

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
	Prov       *oauth2http.ProviderHandler
	Restricted bool
}

func (s *SampleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t, err := s.Prov.Token(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	if s.Restricted {
		fmt.Fprintf(w, `<h3>Restricted</h3>`)
	}
	if t != nil {
		fmt.Fprintf(w, `
		  <p>Logged in | <a href="%s">Log out</a></p>
	  `, s.Prov.LogoutURL("/"))
	} else {
		fmt.Fprintf(w, `
		  <p><a href="%s">Log in</a> | Logged out</p>
	  `, s.Prov.LoginURL(r.RequestURI, false))
	}
	if !s.Restricted {
		fmt.Fprintf(w, `
	    <p><a href="/restricted">Restricted</a></p>
    `)
	}
}

func main() {
	flagfile.Load()
	setup.MustSetup("example")
	monitor.RegisterEnvironment()
	go http.ListenAndServe(*debugAddr, monitor.DefaultStore)

	store := sessions.NewCookieStore([]byte(*cookieSecret))

	oauth := oauth2http.NewProviderHandler(
		oauth2http.Github(&oauth2.Options{
			ClientID:     "<client_id>",
			ClientSecret: "<client_secret>"}),
		oauth2http.SessionFromStore(store, "oauth-github"), "/auth",
		oauth2http.RedirectURLs{})

	logger.Notice("listening")

	http.ListenAndServe(*listenAddr,
		utils.LoggingHandler(context.ClearHandler(
			utils.DirMux{
				"": &SampleHandler{Prov: oauth, Restricted: false},
				"restricted": oauth.LoginRequired(
					&SampleHandler{Prov: oauth, Restricted: true}),
				"auth": oauth})))
}
