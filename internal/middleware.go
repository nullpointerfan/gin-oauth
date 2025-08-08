package internal

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func (am *GinOAuth) refreshToken(oldToken *oauth2.Token) (*oauth2.Token, error) {
	if !oldToken.Valid() {
		oldToken.Expiry = time.Now()
	}

	ctx := context.Background()
	source := am.Config.TokenSource(ctx, oldToken)
	return source.Token()
}

func (am *GinOAuth) OnAuthenticateSuccess(fn func(c *gin.Context) error) {
	am.onAuthenticateSuccess = fn
}

func (am *GinOAuth) Authenticate(c *gin.Context) {
	token, err := GetToken(c, am)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Check token expire
	if !token.Valid() {
		token, err = am.refreshToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "failed to refresh token"})
			return
		}

		SetAuthCookies(c, token, am)
	}
	c.Set(am.Keys.TOKEN, token)

	userData, err := GetUserData(c, token, am)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}
	c.Set(am.Keys.USER, userData)

	if am.onAuthenticateSuccess != nil {
		if err := am.onAuthenticateSuccess(c); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
	}

	c.Next()
}
