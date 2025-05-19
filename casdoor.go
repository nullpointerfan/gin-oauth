package ginoauth

import (
	"net/http"

	"golang.org/x/oauth2"
)

type CasdoorConfig struct {
	OAuthConfig
	CasdoorHost string
}

func NewCasdoorAuth(config CasdoorConfig) *GinOAuth {
	return &GinOAuth{
		config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       append([]string{"email"}, config.Scopes...),
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.CasdoorHost + "/login/oauth/authorize",
				TokenURL: config.CasdoorHost + "/api/login/oauth/access_token",
			},
		},
		jwtSecret:         config.Secret,
		userInfoURL:       config.CasdoorHost + "/api/userinfo",
		httpClient:        http.DefaultClient,
		keys:              getDefaultKeys(),
		staticRedirectURL: config.RedirectURL,
		getRedirectURL:    config.CallbackRedirectURL,
	}
}
