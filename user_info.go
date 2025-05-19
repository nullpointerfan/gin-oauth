package ginoauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

type OnUpdateUserInfoFunc func(userInfo *UserInfoResponse) error

func (am *GinOAuth) OnUpdateUserInfo(fn OnUpdateUserInfoFunc) {
	am.onUpdateUserInfo = fn
}

func (am *GinOAuth) getUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfoResponse, error) {
	client := am.config.Client(ctx, token)
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

	var info UserInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, err
	}

	if am.onUpdateUserInfo != nil {
		if err := am.onUpdateUserInfo(&info); err != nil {
			return nil, err
		}
	}

	return &info, nil
}
