# Ginoauth — OAuth2 Library for Gin in Go

`ginoauth` is a Go library that simplifies the integration of OAuth2 authentication into applications built with the [Gin](https://github.com/gin-gonic/gin) web framework. It supports providers such as Google and Casdoor.

## Features

- Easy OAuth2 authentication integration with Gin.
- Support for multiple providers (Google, Casdoor).
- Token and user data stored in signed and compressed cookies.
- Token refresh mechanism for expired tokens.
- Fetching user information from the provider.
- Flexible hooks: `OnAuthenticateSuccess`, `OnUpdateUserInfo`.

---

## Installation

```bash
go get github.com/nullpointerfan/gin-oauth
```

---

## Quick Start

### 1. Configure the Client

#### For Google:
```go
import (
	"github.com/nullpointerfan/gin-oauth"
)

cfg := ginoauth.GoogleConfig{
	OAuthConfig: ginoauth.OAuthConfig{
		ClientID:     "your-google-client-id",
		ClientSecret: "your-google-client-secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		Secret:       []byte("your-jwt-secret"),
	},
}

auth := ginoauth.NewGoogleAuth(cfg)
```

#### For Casdoor:
```go
cfg := ginoauth.CasdoorConfig{
	OAuthConfig: ginoauth.OAuthConfig{
		ClientID:     "casdoor-client-id",
		ClientSecret: "casdoor-client-secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		Secret:       []byte("your-jwt-secret"),
	},
	CasdoorHost: "https://your-casdoor-host",
}

auth := ginoauth.NewCasdoorAuth(cfg)
```

---

### 2. Setup Routes

```go
r := gin.Default()

r.GET("/login", auth.LoginHandler)
r.GET("/auth/callback", auth.CallbackHandler)
r.GET("/logout", auth.LogoutHandler)

// Protected route
protected := r.Group("/")
protected.Use(auth.Authenticate)
{
	protected.GET("/profile", func(c *gin.Context) {
		user, _ := c.Get("user")
		c.JSON(200, gin.H{"user": user})
	})
}
```

---

## Authentication

- OAuth2 tokens are stored in secure cookies with HMAC signature and gzip compression.
- When a token expires, it's automatically refreshed using the `refresh_token`.
- User information is also stored in cookies and can be extended via `OnUpdateUserInfo`.

---

## Hooks

### `OnUpdateUserInfo`
Called after receiving user data from the provider. Useful for adding custom fields or logic:

```go
auth.OnUpdateUserInfo(func(userInfo *ginoauth.UserInfoResponse) error {
	userInfo.Name = strings.ToUpper(userInfo.Name)
	return nil
})
```

### `OnAuthenticateSuccess`
Executed upon successful authentication:

```go
auth.OnAuthenticateSuccess(func(c *gin.Context) error {
	c.Set("custom_user_data", "some_extra_info")
	return nil
})
```

---

## Logout

To log out a user, simply call `/logout`:

```go
r.GET("/logout", auth.LogoutHandler)
```

This will remove all session-related data (tokens and user info).
