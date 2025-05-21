package internal

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type KeyCookie string

const (
	TOKEN       KeyCookie = "oauth_token"
	OAUTH_STATE KeyCookie = "oauth_state"
	USER        KeyCookie = "user"
)

type Keys struct {
	COOKIE_TOKEN string
	COOKIE_USER  string
	OAUTH_STATE  string
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
	JwtSecret             []byte
	Config                *oauth2.Config
	UserInfoURL           string
	HttpClient            *http.Client
	Keys                  *Keys
	StaticRedirectURL     string
	GetRedirectURL        func(c *gin.Context) string
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
