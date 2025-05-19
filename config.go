package ginoauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type KeyCookie string

const (
	TOKEN KeyCookie = "oauth_token"
	USER  KeyCookie = "user"
)

type Keys struct {
	COOKIE_TOKEN string
	COOKIE_USER  string
}

type OAuthConfig struct {
	ClientID            string
	ClientSecret        string
	Scopes              []string
	Secret              []byte
	RedirectURL         string
	CallbackRedirectURL func(c *gin.Context) string
}

type GinOAuth struct {
	jwtSecret             []byte
	config                *oauth2.Config
	userInfoURL           string
	httpClient            *http.Client
	keys                  *Keys
	staticRedirectURL     string
	getRedirectURL        func(c *gin.Context) string
	onUpdateUserInfo      func(*UserInfoResponse) error
	onAuthenticateSuccess func(c *gin.Context) error
}

type TokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Expiry       int64  `json:"expiry"`
}

type UserInfoResponse struct {
	Subject string `json:"sub"`
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}
