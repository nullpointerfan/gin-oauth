package ginoauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

func signToken(data []byte, am *AuthModule) string {
	mac := hmac.New(sha256.New, am.jwtSecret)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func verifySignature(data, sig string, am *AuthModule) bool {
	mac := hmac.New(sha256.New, am.jwtSecret)
	mac.Write([]byte(data))
	expectedSignature := mac.Sum(nil)
	signature, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	return hmac.Equal(expectedSignature, signature)
}

func getSignPayload(value string) (string, string, error) {
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("incorrect value")
	}
	jsonData := strings.Join(parts[0:len(parts)-1], ".")
	sign := parts[len(parts)-1]
	return jsonData, sign, nil
}

func setVerifyCookie(c *gin.Context, am *AuthModule, data interface{}, cookie *http.Cookie) {
	b, _ := json.Marshal(data)
	signed := string(b) + "." + signToken(b, am)

	compressedToken, err := CompressJWT(signed)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to compress token"})
		return
	}

	cookie.Value = url.QueryEscape(compressedToken)
	http.SetCookie(c.Writer, cookie)
}

func getVerifyCookie(c *gin.Context, am *AuthModule, key string, out interface{}) error {
	cookie, err := c.Cookie(key)
	if err != nil {
		return fmt.Errorf("key not exist")
	}

	cookie, err = DecompressJWT(cookie)
	if err != nil {
		return fmt.Errorf("failed to decompress token")
	}

	data, sign, err := getSignPayload(cookie)
	if err != nil {
		return fmt.Errorf("failed get sign payload")
	}

	if !verifySignature(data, sign, am) {
		return fmt.Errorf("invalid token data")
	}

	if err := json.Unmarshal([]byte(data), &out); err != nil {
		return fmt.Errorf("invalid unmarshal data")
	}
	return nil
}
