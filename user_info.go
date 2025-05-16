package ginoauth

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"golang.org/x/oauth2"
)

type OnUserAuthenticatedCallbackFunc func(userInfo *UserInfoResponse) error

func (am *AuthModule) OnUserAuthenticated(fn OnUserAuthenticatedCallbackFunc) {
	am.onUserAuthenticated = fn
}

func (am *AuthModule) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfoResponse, error) {
	client := am.Config.Client(ctx, token)
	req, _ := http.NewRequest("GET", am.userInfoURL, nil)
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.Println(string(body))

	var info UserInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	if am.onUserAuthenticated != nil {
		if err := am.onUserAuthenticated(&info); err != nil {
			return nil, err
		}
	}

	return &info, nil
}
