package ginoauth

import (
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleConfig struct {
	OAuthConfig
}

func NewGoogleAuth(config GoogleConfig) *AuthModule {
	return &AuthModule{
		jwtSecret: config.Secret,
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
		userInfoURL:      "https://www.googleapis.com/oauth2/v2/userinfo",
		httpClient:       http.DefaultClient,
		KEYS:             getDefaultKeys(),
		RedirectCallback: config.RedirectCallback,
	}
}
