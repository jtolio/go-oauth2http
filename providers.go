// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2http

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
)

// Provider is a named *oauth2.Config
type Provider struct {
	Name string
	oauth2.Config
}

func Github(conf oauth2.Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = github.Endpoint
	}
	return &Provider{
		Name:   "github",
		Config: conf}
}

func Google(conf oauth2.Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = google.Endpoint
	}
	return &Provider{
		Name:   "google",
		Config: conf}
}

func Facebook(conf oauth2.Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = facebook.Endpoint
	}
	return &Provider{
		Name:   "facebook",
		Config: conf}
}

func LinkedIn(conf oauth2.Config) *Provider {
	if conf.Endpoint.AuthURL == "" {
		conf.Endpoint = linkedin.Endpoint
	}
	return &Provider{
		Name:   "linkedin",
		Config: conf}
}
