package provider

import (
	"net/http"

	"github.com/nullpointerfan/gin-oauth/internal"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleConfig struct {
	internal.OAuthConfig
}

func NewGoogleAuth(config GoogleConfig) *internal.GinOAuth {
	return &internal.GinOAuth{
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
		Keys:              internal.GetDefaultKeys(),
		StaticRedirectURL: config.RedirectURL,
		GetRedirectURL:    config.CallbackRedirectURL,
	}
}
