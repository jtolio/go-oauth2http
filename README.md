go-oauth2http
=============

*Update 2015-06-30:* this project now builds and works again, but conventions
around Go development are moving fast around here. It's likely this project
does this all wrong (I now question the need for the Gorilla deps, for
example).

Go library for easily adding required oauth2 resources.

Design goal is to be simple to configure, modular, easy to add, and work
with just net/http.

See http://godoc.org/github.com/jtolds/go-oauth2http

Also see the examples at:
https://github.com/jtolds/go-oauth2http/blob/master/examples/group/main.go
https://github.com/jtolds/go-oauth2http/blob/master/examples/one/main.go

Contrast to https://github.com/GoIncremental/negroni-oauth2, which requires
negroni.

Since this package uses github.com/gorilla/sessions (and therefore,
github.com/gorilla/context), make sure to use context.ClearHandler or similar.
