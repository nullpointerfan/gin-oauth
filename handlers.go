package ginoauth

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	InvalidState        error = errors.New("invalid state")
	FailedExchangeToken error = errors.New("failed to exchange token")
	RedirectURLNotSet   error = errors.New("redirect url not set")
)

func (am *GinOAuth) CheckStateAndExchangeToken(c *gin.Context) error {
	state := c.Query("state")
	if state != "state-token" {
		return InvalidState
	}

	code := c.Query("code")
	token, err := am.config.Exchange(c, code)
	if err != nil {
		return FailedExchangeToken
	}

	SetAuthCookies(c, token, am)
	ClearUserDataCookies(c, am)

	return err
}

func (am *GinOAuth) getRedirect(c *gin.Context) (string, error) {
	if am.getRedirectURL == nil {
		if am.staticRedirectURL == "" {
			return "", RedirectURLNotSet
		} else {
			return am.staticRedirectURL, nil
		}
	} else {
		return am.getRedirectURL(c), nil
	}
}

func (am *GinOAuth) LoginHandler(c *gin.Context) {
	redirectUrl, err := am.getRedirect(c)
	if err != nil {
		c.Writer.Write([]byte(err.Error()))
		return
	}
	am.config.RedirectURL = redirectUrl
	url := am.config.AuthCodeURL("state-token")
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (am *GinOAuth) CallbackHandler(c *gin.Context) {
	if err := am.CheckStateAndExchangeToken(c); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "authorized"})
}

func (am *GinOAuth) LogoutHandler(c *gin.Context) {
	ClearAuthCookies(c, am)
	ClearUserDataCookies(c, am)
}

func (am *GinOAuth) SetCallbackRedirectURL(fn func(c *gin.Context) string) {
	am.getRedirectURL = fn
}
