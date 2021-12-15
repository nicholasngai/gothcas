package gothcas

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"

	"github.com/markbates/goth"
	"gopkg.in/cas.v2"
)

// Session is a CAS authentication session.
type Session struct {
	AuthURL     *url.URL
	CallbackURL  *url.URL
	CASResponse *cas.AuthenticationResponse
}

// GetAuthURL return CAS authentication URL for the session.
func (s *Session) GetAuthURL() (string, error) {
	authUrl := s.AuthURL
	authUrl = authUrl.ResolveReference(&url.URL{Path: "cas/login"})
	query := authUrl.Query()
	if authUrl.Query().Has("service") {
		return "", errors.New("Auth URL already has serivce parameter")
	}
	query.Add("service", s.CallbackURL.String())
	authUrl.RawQuery = query.Encode()
	return authUrl.String(), nil
}

// Marshal returns a string representation of the session.
func (s *Session) Marshal() string {
	marshaled, _ := json.Marshal(s)
	return string(marshaled)
}

// Authorize validates the CAS ticket against the server, stores it, and
// returns the ticket.
func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	var err error

	p := provider.(*Provider)

	ticket := params.Get("ticket")
	casUrl := s.AuthURL
	casUrl.Path = path.Join(casUrl.Path, "cas")
	validator := cas.NewServiceTicketValidator(http.DefaultClient, casUrl)
	s.CASResponse, err = validator.ValidateTicket(p.callbackUrl, ticket)
	if err != nil {
		return "", err
	}

	return ticket, nil
}
