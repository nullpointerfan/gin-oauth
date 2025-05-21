package ginoauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nullpointerfan/gin-oauth/internal"
)

func setupTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest("GET", "/test", nil)
	c.Request = req
	return c, w
}

func TestGenerateRandomState(t *testing.T) {
	state1 := internal.GenerateRandomState(16)
	state2 := internal.GenerateRandomState(16)

	if len(state1) != 16 {
		t.Errorf("expected state length of 16, got %d", len(state1))
	}

	if state1 == state2 {
		t.Errorf("generated states are the same, expected randomness")
	}
}

func TestInvalidState(t *testing.T) {
	c, _ := setupTestContext()
	am := &internal.GinOAuth{
		Keys: &internal.Keys{
			OAUTH_STATE: "oauth_state",
		},
	}

	expectedState := "correct-state"
	internal.SetCookie(c, am.Keys.OAUTH_STATE, expectedState, time.Now().Add(3600*time.Second))

	// Send wrong state
	c.Request.Form = make(map[string][]string)
	c.Request.Form.Add("state", "wrong-state")
	c.Request.Form.Add("code", "test-code")

	err := am.CheckStateAndExchangeToken(c)
	if err == nil || err.Error() != "invalid state" {
		t.Errorf("expected 'invalid state' error, got %v", err)
	}
}

func TestMissingStateInCookie(t *testing.T) {
	c, _ := setupTestContext()
	am := &internal.GinOAuth{
		Keys: &internal.Keys{
			OAUTH_STATE: "oauth_state",
		},
	}

	// Send request without setting state cookie
	c.Request.Form = make(map[string][]string)
	c.Request.Form.Add("state", "some-state")
	c.Request.Form.Add("code", "test-code")

	err := am.CheckStateAndExchangeToken(c)
	if err == nil || err.Error() != "invalid state" {
		t.Errorf("expected 'invalid state' error for missing cookie, got %v", err)
	}
}
