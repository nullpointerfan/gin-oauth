package ginoauth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (am *AuthModule) OnCustomEndCallback(fn func(c *gin.Context) error) {
	am.onCustomEndCallback = fn
}

func (am *AuthModule) LoginHandler(c *gin.Context) {
	am.Config.RedirectURL = am.RedirectCallback(c)
	url := am.Config.AuthCodeURL("state-token")
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (am *AuthModule) CallbackHandler(c *gin.Context) {
	state := c.Query("state")
	if state != "state-token" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid state"})
		return
	}

	code := c.Query("code")
	token, err := am.Config.Exchange(c, code)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to exchange token"})
		return
	}

	SetAuthCookies(c, token, am)
	ClearUserDataCookies(c, am)

	if am.onCustomEndCallback != nil {
		if err := am.onCustomEndCallback(c); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		c.JSON(http.StatusOK, gin.H{"status": "authorized"})
	}
}

func (am *AuthModule) LogoutHandler(c *gin.Context) {
	ClearAuthCookies(c, am)
	ClearUserDataCookies(c, am)
}

func (am *AuthModule) RefreshHandler(c *gin.Context) {
	token, err := GetAuthCookies(c, am)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	newToken, err := am.Config.TokenSource(c, token).Token()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh token"})
		return
	}

	SetAuthCookies(c, newToken, am)
	c.IndentedJSON(http.StatusOK, newToken)
}
