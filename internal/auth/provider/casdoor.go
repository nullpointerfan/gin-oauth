package provider

import (
	"net/http"

	"github.com/nullpointerfan/gin-oauth/internal"
	"golang.org/x/oauth2"
)

type CasdoorConfig struct {
	internal.OAuthConfig
	CasdoorHost string
}

func NewCasdoorAuth(config CasdoorConfig) *internal.GinOAuth {
	return &internal.GinOAuth{
		Config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       append([]string{"email"}, config.Scopes...),
			Endpoint: oauth2.Endpoint{
				AuthURL:  config.CasdoorHost + "/login/oauth/authorize",
				TokenURL: config.CasdoorHost + "/api/login/oauth/access_token",
			},
		},
		JwtSecret:         config.Secret,
		UserInfoURL:       config.CasdoorHost + "/api/userinfo",
		HttpClient:        http.DefaultClient,
		Keys:              internal.GetDefaultKeys(),
		StaticRedirectURL: config.RedirectURL,
		GetRedirectURL:    config.CallbackRedirectURL,
	}
}
