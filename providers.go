// Copyright (C) 2014 JT Olds
// See LICENSE for copying information

package oauth2http

import (
	"github.com/golang/oauth2"
)

// Provider is a named *oauth2.Config
type Provider struct {
	Name string
	*oauth2.Config
}

func Github(opts *oauth2.Options) *Provider {
	conf, err := oauth2.NewConfig(opts,
		"https://github.com/login/oauth/authorize",
		"https://github.com/login/oauth/access_token")
	if err != nil {
		panic(err)
	}
	return &Provider{
		Name:   "github",
		Config: conf}
}

func Google(opts *oauth2.Options) *Provider {
	conf, err := oauth2.NewConfig(opts,
		"https://accounts.google.com/o/oauth2/auth",
		"https://accounts.google.com/o/oauth2/token")
	if err != nil {
		panic(err)
	}
	return &Provider{
		Name:   "google",
		Config: conf}
}

func Facebook(opts *oauth2.Options) *Provider {
	conf, err := oauth2.NewConfig(opts,
		"https://www.facebook.com/dialog/oauth",
		"https://graph.facebook.com/oauth/access_token")
	if err != nil {
		panic(err)
	}
	return &Provider{
		Name:   "facebook",
		Config: conf}
}

func LinkedIn(opts *oauth2.Options) *Provider {
	conf, err := oauth2.NewConfig(opts,
		"https://www.linkedin.com/uas/oauth2/authorization",
		"https://www.linkedin.com/uas/oauth2/accessToken")
	if err != nil {
		panic(err)
	}
	return &Provider{
		Name:   "linkedin",
		Config: conf}
}
