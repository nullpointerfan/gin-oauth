package ginoauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	ErrInvalidState        error = errors.New("invalid state")
	ErrFailedExchangeToken error = errors.New("failed to exchange token")
	ErrRedirectURLNotSet   error = errors.New("redirect url not set")
)

func (am *GinOAuth) CheckStateAndExchangeToken(c *gin.Context) error {
	expectedState, err := c.Cookie(am.Keys.OAUTH_STATE)
	if err != nil || expectedState == "" {
		return ErrInvalidState
	}

	state := c.Query("state")
	if state != expectedState {
		return ErrInvalidState
	}

	code := c.Query("code")
	token, err := am.Config.Exchange(c, code)
	if err != nil {
		return ErrFailedExchangeToken
	}

	SetAuthCookies(c, token, am)
	ClearUserDataCookies(c, am)
	SetCookie(c, am.Keys.OAUTH_STATE, "", time.Now().Add(-1*time.Second))

	return err
}

func (am *GinOAuth) getRedirect(c *gin.Context) (string, error) {
	if am.GetRedirectURL == nil {
		if am.StaticRedirectURL == "" {
			return "", ErrRedirectURLNotSet
		} else {
			return am.StaticRedirectURL, nil
		}
	} else {
		return am.GetRedirectURL(c), nil
	}
}

func (am *GinOAuth) LoginHandler(c *gin.Context) {
	redirectUrl, err := am.getRedirect(c)
	if err != nil {
		c.Writer.Write([]byte(err.Error()))
		return
	}
	am.Config.RedirectURL = redirectUrl
	state := "state-" + GenerateRandomState(16)
	SetCookie(c, am.Keys.OAUTH_STATE, state, time.Now().Add(3600*time.Second))
	url := am.Config.AuthCodeURL(state)
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
	am.GetRedirectURL = fn
}
