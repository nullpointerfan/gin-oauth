package internal

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func GetDefaultKeys() *Keys {
	return &Keys{
		COOKIE_TOKEN: string(TOKEN),
		COOKIE_USER:  string(USER),
		OAUTH_STATE:  string(OAUTH_STATE),
	}
}

func SetCookie(c *gin.Context, key, value string, expires time.Time) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     key,
		Value:    value,
		Expires:  expires,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})
}

func SetAuthCookies(c *gin.Context, token *oauth2.Token, am *GinOAuth) {
	data := TokenData{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry.Unix(),
	}
	setVerifyCookie(c, am, data, &http.Cookie{
		Name:     am.Keys.COOKIE_TOKEN,
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})
}

func GetAuthCookies(c *gin.Context, am *GinOAuth) (*oauth2.Token, error) {
	var tokenData TokenData
	if err := getVerifyCookie(c, am, am.Keys.COOKIE_TOKEN, &tokenData); err != nil {
		return nil, fmt.Errorf("invalid token data")
	}

	expiry := time.Unix(tokenData.Expiry, 0)
	return &oauth2.Token{
		AccessToken:  tokenData.AccessToken,
		RefreshToken: tokenData.RefreshToken,
		Expiry:       expiry,
	}, nil
}

func ClearAuthCookies(c *gin.Context, am *GinOAuth) {
	c.SetCookie(am.Keys.COOKIE_TOKEN, "", -1, "/", "", c.Request.TLS != nil, true)
}

func setUserDataCookies(c *gin.Context, token *oauth2.Token, am *GinOAuth) (*UserInfoResponse, error) {
	userData, err := am.GetUserInfo(c, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info from provider")
	}

	setVerifyCookie(c, am, userData, &http.Cookie{
		Name:     am.Keys.COOKIE_USER,
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})

	return userData, nil
}

func GetUserData(c *gin.Context, token *oauth2.Token, am *GinOAuth) (*UserInfoResponse, error) {
	var userData UserInfoResponse
	if err := getVerifyCookie(c, am, am.Keys.COOKIE_USER, &userData); err != nil {
		return setUserDataCookies(c, token, am)
	}
	return &userData, nil
}

func ClearUserDataCookies(c *gin.Context, am *GinOAuth) {
	c.SetCookie(am.Keys.COOKIE_USER, "", -1, "/", "", c.Request.TLS != nil, true)
}

func parseToken(c *gin.Context) (*oauth2.Token, error) {
	bearer := c.Request.Header.Get("Authorization")
	if bearer == "" {
		return nil, fmt.Errorf("authorization header is missing")
	}

	array := strings.Fields(bearer)
	if len(array) < 2 {
		return nil, fmt.Errorf("invalid authorization header format")
	}

	tokenType := strings.ToLower(array[0])
	if tokenType != "bearer" {
		return nil, fmt.Errorf("unsupported token type: %s", array[0])
	}

	token := &oauth2.Token{
		AccessToken: array[1],
	}
	return token, nil
}

func GetToken(c *gin.Context, am *GinOAuth) (*oauth2.Token, error) {
	token, err := parseToken(c)
	if err == nil {
		return token, err
	}
	return GetAuthCookies(c, am)
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

func GenerateRandomState(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
