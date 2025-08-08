package ginoauth

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

func GetDefaultKeys() *Keys {
	return &Keys{
		COOKIE_ACCESS_TOKEN:  string(COOKIE_ACCESS_TOKEN),
		COOKIE_REFRESH_TOKEN: string(COOKIE_REFRESH_TOKEN),
		COOKIE_EXPIRE_TOKEN:  string(COOKIE_EXPIRE_TOKEN),
		TOKEN:                string(TOKEN),
		USER:                 string(USER),
		OAUTH_STATE:          string(OAUTH_STATE),
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
	setCookie(c, &http.Cookie{
		Name:     am.Keys.COOKIE_ACCESS_TOKEN,
		Value:    token.AccessToken,
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})
	setCookie(c, &http.Cookie{
		Name:     am.Keys.COOKIE_REFRESH_TOKEN,
		Value:    token.RefreshToken,
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})
	setCookie(c, &http.Cookie{
		Name:     am.Keys.COOKIE_EXPIRE_TOKEN,
		Value:    fmt.Sprintf("%v", token.Expiry.Unix()),
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})
}

func GetAuthCookies(c *gin.Context, am *GinOAuth) (*oauth2.Token, error) {
	access, err := getCookie(c, am.Keys.COOKIE_ACCESS_TOKEN)
	if err != nil {
		return nil, fmt.Errorf("invalid token data")
	}
	refresh, err := getCookie(c, am.Keys.COOKIE_REFRESH_TOKEN)
	if err != nil {
		return nil, fmt.Errorf("invalid token data")
	}
	expire, err := getCookie(c, am.Keys.COOKIE_EXPIRE_TOKEN)
	if err != nil {
		return nil, fmt.Errorf("invalid token data")
	}
	e, err := strconv.ParseInt(expire, 10, 64)
	if err != nil {
		return nil, err
	}
	expiry := time.Unix(e, 0)
	return &oauth2.Token{
		AccessToken:  access,
		RefreshToken: refresh,
		Expiry:       expiry,
	}, nil
}

func ClearAuthCookies(c *gin.Context, am *GinOAuth) {
	c.SetCookie(am.Keys.COOKIE_ACCESS_TOKEN, "", -1, "/", "", c.Request.TLS != nil, true)
	c.SetCookie(am.Keys.COOKIE_REFRESH_TOKEN, "", -1, "/", "", c.Request.TLS != nil, true)
	c.SetCookie(am.Keys.COOKIE_EXPIRE_TOKEN, "", -1, "/", "", c.Request.TLS != nil, true)
}

func setUserDataCookies(c *gin.Context, token *oauth2.Token, am *GinOAuth) (*UserInfoResponse, error) {
	userData, err := am.GetUserInfo(c, token)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user info from provider")
	}

	bytes, err := json.Marshal(userData)
	if err != nil {
		return nil, err
	}

	setCookie(c, &http.Cookie{
		Name:     am.Keys.USER,
		Value:    url.QueryEscape(string(bytes)),
		Expires:  time.Now().Add(3600 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Request.TLS != nil,
	})

	return userData, nil
}

func GetUserData(c *gin.Context, token *oauth2.Token, am *GinOAuth) (*UserInfoResponse, error) {
	var userData UserInfoResponse
	userDataStr, err := getCookie(c, am.Keys.USER)
	if err != nil {
		return setUserDataCookies(c, token, am)
	}
	err = json.Unmarshal([]byte(userDataStr), &userData)
	if err != nil {
		return setUserDataCookies(c, token, am)
	}
	return &userData, nil
}

func ClearUserDataCookies(c *gin.Context, am *GinOAuth) {
	c.SetCookie(am.Keys.USER, "", -1, "/", "", c.Request.TLS != nil, true)
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

func setCookie(c *gin.Context, cookie *http.Cookie) {
	http.SetCookie(c.Writer, cookie)
}

func getCookie(c *gin.Context, key string) (string, error) {
	cookie, err := c.Cookie(key)
	if err != nil {
		return cookie, fmt.Errorf("key not exist")
	}
	return cookie, nil
}
