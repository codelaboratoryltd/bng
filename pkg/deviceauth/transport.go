package deviceauth

import (
	"net/http"
)

// AuthenticatedTransport wraps an http.RoundTripper to add authentication.
type AuthenticatedTransport struct {
	// Base is the underlying transport to use for requests.
	// If nil, http.DefaultTransport is used.
	Base http.RoundTripper

	// Authenticator provides authentication headers and TLS config.
	Authenticator Authenticator
}

// RoundTrip implements http.RoundTripper.
func (t *AuthenticatedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid mutating the original
	reqCopy := req.Clone(req.Context())

	// Add authentication headers
	if t.Authenticator != nil {
		for key, value := range t.Authenticator.GetHTTPHeaders() {
			reqCopy.Header.Set(key, value)
		}
		reqCopy.Header.Set("X-Auth-Mode", string(t.Authenticator.Mode()))
	}

	// Use base transport or default
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	return base.RoundTrip(reqCopy)
}

// NewAuthenticatedClient creates an HTTP client with authentication.
func NewAuthenticatedClient(auth Authenticator) *http.Client {
	var transport http.RoundTripper

	// Get TLS config from authenticator
	tlsConfig := auth.GetTLSConfig()
	if tlsConfig != nil {
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	// Wrap with authenticated transport
	authTransport := &AuthenticatedTransport{
		Base:          transport,
		Authenticator: auth,
	}

	return &http.Client{
		Transport: authTransport,
	}
}

// WrapHTTPClient wraps an existing HTTP client with authentication.
func WrapHTTPClient(client *http.Client, auth Authenticator) *http.Client {
	// Get the base transport
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	// Get TLS config from authenticator
	tlsConfig := auth.GetTLSConfig()
	if tlsConfig != nil {
		// If we have TLS config, we need to create a new transport
		if httpTransport, ok := base.(*http.Transport); ok {
			// Clone the transport and add TLS config
			newTransport := httpTransport.Clone()
			newTransport.TLSClientConfig = tlsConfig
			base = newTransport
		} else {
			// Create a new transport with TLS config
			base = &http.Transport{
				TLSClientConfig: tlsConfig,
			}
		}
	}

	// Wrap with authenticated transport
	authTransport := &AuthenticatedTransport{
		Base:          base,
		Authenticator: auth,
	}

	// Create a new client with same settings but authenticated transport
	return &http.Client{
		Transport:     authTransport,
		CheckRedirect: client.CheckRedirect,
		Jar:           client.Jar,
		Timeout:       client.Timeout,
	}
}

// AuthenticatedRoundTripper returns a round tripper that adds authentication.
// This is useful when you need to customize the transport further.
func AuthenticatedRoundTripper(base http.RoundTripper, auth Authenticator) http.RoundTripper {
	return &AuthenticatedTransport{
		Base:          base,
		Authenticator: auth,
	}
}
