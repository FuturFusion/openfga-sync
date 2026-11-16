// Package httpclient builds the HTTP clients used to reach external services.
package httpclient

import (
	"crypto/tls"
	"net/http"
	"time"
)

// requestTimeout bounds the duration of a single request, including reading the response.
const requestTimeout = time.Minute

// New returns an HTTP client using the given TLS configuration, keeping the
// connection pooling and timeouts of the default transport.
func New(tlsConfig *tls.Config) *http.Client {
	transport := &http.Transport{}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		transport = defaultTransport.Clone()
	}

	transport.TLSClientConfig = tlsConfig

	return &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}
}
