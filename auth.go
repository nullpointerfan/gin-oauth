package ginoauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func getDefaultKeys() *Keys {
	return &Keys{
		COOKIE_TOKEN: string(TOKEN),
		COOKIE_USER:  string(USER),
	}
}

func (am *AuthModule) RefreshToken(oldToken *oauth2.Token) (*oauth2.Token, error) {
	if !oldToken.Valid() {
		oldToken.Expiry = time.Now()
	}

	ctx := context.Background()
	source := am.Config.TokenSource(ctx, oldToken)
	return source.Token()
}

func SetAuthCookies(c *gin.Context, token *oauth2.Token, am *AuthModule) {
	data := TokenData{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry.Unix(),
	}
	setVerifyCookie(c, am, data, &http.Cookie{
		Name:     am.KEYS.COOKIE_TOKEN,
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})
}

func GetAuthCookies(c *gin.Context, am *AuthModule) (*oauth2.Token, error) {
	var tokenData TokenData
	if err := getVerifyCookie(c, am, am.KEYS.COOKIE_TOKEN, &tokenData); err != nil {
		return nil, fmt.Errorf("invalid token data")
	}

	expiry := time.Unix(tokenData.Expiry, 0)
	return &oauth2.Token{
		AccessToken:  tokenData.AccessToken,
		RefreshToken: tokenData.RefreshToken,
		Expiry:       expiry,
	}, nil
}

func ClearAuthCookies(c *gin.Context, am *AuthModule) {
	c.SetCookie(am.KEYS.COOKIE_TOKEN, "", -1, "/", "", c.Request.TLS != nil, true)
}

func SetUserDataCookies(c *gin.Context, token *oauth2.Token, am *AuthModule) (*UserInfoResponse, error) {
	userData, err := am.GetUserInfo(c, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info from provider")
	}

	setVerifyCookie(c, am, userData, &http.Cookie{
		Name:     am.KEYS.COOKIE_USER,
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})

	return userData, nil
}

func GetUserData(c *gin.Context, token *oauth2.Token, am *AuthModule) (*UserInfoResponse, error) {
	var userData UserInfoResponse
	if err := getVerifyCookie(c, am, am.KEYS.COOKIE_USER, &userData); err != nil {
		return SetUserDataCookies(c, token, am)
	}
	return &userData, nil
}

func ClearUserDataCookies(c *gin.Context, am *AuthModule) {
	c.SetCookie(am.KEYS.COOKIE_USER, "", -1, "/", "", c.Request.TLS != nil, true)
}
