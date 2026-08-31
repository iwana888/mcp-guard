package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("missing scheme or host: %q", s)
	}
	return u, nil
}

func listenAndServe(addr string, h http.Handler) error {
	return http.ListenAndServe(addr, h)
}
