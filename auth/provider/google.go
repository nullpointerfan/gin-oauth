package provider

import (
	"net/http"

	ginoauth "github.com/nullpointerfan/gin-oauth"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleConfig struct {
	ginoauth.OAuthConfig
}

func NewGoogleAuth(config GoogleConfig) *ginoauth.GinOAuth {
	return &ginoauth.GinOAuth{
		JwtSecret: config.Secret,
		Config: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       append([]string{"https://www.googleapis.com/auth/userinfo.email "}, config.Scopes...),
			Endpoint: oauth2.Endpoint{
				AuthURL:       google.Endpoint.AuthURL + "?access_type=offline&prompt=consent",
				DeviceAuthURL: google.Endpoint.DeviceAuthURL,
				TokenURL:      google.Endpoint.TokenURL,
				AuthStyle:     google.Endpoint.AuthStyle,
			},
		},
		UserInfoURL:       "https://www.googleapis.com/oauth2/v2/userinfo",
		HttpClient:        http.DefaultClient,
		Keys:              ginoauth.GetDefaultKeys(),
		StaticRedirectURL: config.RedirectURL,
		GetRedirectURL:    config.CallbackRedirectURL,
	}
}
