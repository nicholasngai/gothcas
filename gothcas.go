package gothcas

import (
	"encoding/json"
	"errors"
	"net/url"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

// AttributeMap defines the relationship between CAS attributes and the goth
// user definition.
type AttributeMap struct {
	Email       string
	Name        string
	FirstName   string
	LastName    string
	NickName    string
	Description string
	UserID      string
	AvatarURL   string
	Location    string
}

// Provider is an implementation of `goth.Provider` to authenticate against a
// CAS URL.
type Provider struct {
	name         string
	authUrl      *url.URL
	callbackUrl  *url.URL
	attributeMap *AttributeMap
}

// New constructs a Provider with with the given parameters.
func New(authUrl string, callbackUrl string, attributeMap *AttributeMap) (*Provider, error) {
	var err error

	authUrlParsed, err := url.Parse(authUrl)
	if err != nil {
		return nil, err
	}
	callbackUrlParsed, err := url.Parse(callbackUrl)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		name:         "cas",
		authUrl:      authUrlParsed,
		callbackUrl:  callbackUrlParsed,
		attributeMap: attributeMap,
	}

	return p, nil
}

// Name returns the name of the provider.
func (p *Provider) Name() string {
	return p.name
}

// SetName sets the name of the provider.
func (p *Provider) SetName(name string) {
	p.name = name
}

// BeginAuth returns a session that uses the desired authUrl.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	s := &Session{
		AuthURL:     p.authUrl,
		CallbackURL: p.callbackUrl,
	}

	return s, nil
}

// UnmarshalSession returns the session represented by the given string.
func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.Unmarshal([]byte(data), s)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// FetchUser queries the CAS validation endpoint to retrieve user attributes.
func (p *Provider) FetchUser(sess goth.Session) (goth.User, error) {
	s := sess.(*Session)
	if s.CASResponse == nil {
		return goth.User{}, errors.New("User information has not yet been fetched")
	}

	rawData := make(map[string]interface{}, len(s.CASResponse.Attributes))
	for key, val := range s.CASResponse.Attributes {
		rawData[key] = val
	}

	u := goth.User{
		RawData:     rawData,
		Provider:    p.Name(),
		Email:       s.CASResponse.Attributes.Get(p.attributeMap.Email),
		Name:        s.CASResponse.Attributes.Get(p.attributeMap.Name),
		FirstName:   s.CASResponse.Attributes.Get(p.attributeMap.FirstName),
		LastName:    s.CASResponse.Attributes.Get(p.attributeMap.LastName),
		NickName:    s.CASResponse.Attributes.Get(p.attributeMap.NickName),
		Description: s.CASResponse.Attributes.Get(p.attributeMap.Description),
		UserID:      s.CASResponse.Attributes.Get(p.attributeMap.UserID),
		AvatarURL:   s.CASResponse.Attributes.Get(p.attributeMap.AvatarURL),
		Location:    s.CASResponse.Attributes.Get(p.attributeMap.Location),
	}

	return u, nil
}

// Debug is a no-op.
func (p *Provider) Debug(debug bool) {}

// RefreshToken is not implemented.
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return nil, nil
}

// RefreshTokenAvailable returns false, because RefreshToken is not
// implemented.
func (p *Provider) RefreshTokenAvailable() bool {
	return false
}
