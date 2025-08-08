package ginoauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type KeyCookie string

const (
	COOKIE_ACCESS_TOKEN  KeyCookie = "access_token"
	COOKIE_REFRESH_TOKEN KeyCookie = "refresh_token"
	COOKIE_EXPIRE_TOKEN  KeyCookie = "expire_token"
	TOKEN                KeyCookie = "token"
	OAUTH_STATE          KeyCookie = "oauth_state"
	USER                 KeyCookie = "user"
)

type Keys struct {
	COOKIE_ACCESS_TOKEN  string
	COOKIE_REFRESH_TOKEN string
	COOKIE_EXPIRE_TOKEN  string
	TOKEN                string
	OAUTH_STATE          string
	USER                 string
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

type UserInfoResponse struct {
	Subject string `json:"sub"`
	ID      string `json:"id"`
	Email   string `json:"email"`
	Name    string `json:"name"`
}
