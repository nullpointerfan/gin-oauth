package ginoauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (am *AuthModule) OnMiddleWareSuccess(fn func(c *gin.Context) error) {
	am.onMiddleWareSuccess = fn
}

func AuthMiddleware(am *AuthModule) gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := GetAuthCookies(c, am)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		// Check token expire
		if !token.Valid() {
			token, err = am.RefreshToken(token)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "failed to refresh token"})
				return
			}

			SetAuthCookies(c, token, am)
		}
		c.Set(am.KEYS.COOKIE_TOKEN, token)

		userData, err := GetUserData(c, token, am)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.Set(am.KEYS.COOKIE_USER, userData)

		if am.onMiddleWareSuccess != nil {
			if err := am.onMiddleWareSuccess(c); err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				return
			}
		}

		c.Next()
	}
}
