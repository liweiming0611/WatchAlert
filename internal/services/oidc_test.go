package services

import (
	"net/url"
	"testing"
)

func TestBuildAuthorizeURL(t *testing.T) {
	q := url.Values{}
	q.Set("client_id", "watchalert")
	q.Set("state", "abc")

	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "端点不带 query",
			endpoint: "https://gitlab.example.com/oauth/authorize",
			want:     "https://gitlab.example.com/oauth/authorize?client_id=watchalert&state=abc",
		},
		{
			// 部分 IdP 的 authorization_endpoint 自带固化参数, 必须用 & 追加而不是再拼一个 ?
			name:     "端点自带 query",
			endpoint: "https://idp.example.com/authorize?tenant=ur",
			want:     "https://idp.example.com/authorize?tenant=ur&client_id=watchalert&state=abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildAuthorizeURL(tt.endpoint, q); got != tt.want {
				t.Errorf("buildAuthorizeURL(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestBuildLogoutURL(t *testing.T) {
	tests := []struct {
		name                  string
		endSessionEndpoint    string
		clientID              string
		postLogoutRedirectURI string
		want                  string
	}{
		{
			name:                  "IdP 支持 RP-Initiated Logout",
			endSessionEndpoint:    "https://idp.example.com/logout",
			clientID:              "watchalert",
			postLogoutRedirectURI: "https://w8t.example.com/login",
			want:                  "https://idp.example.com/logout?client_id=watchalert&post_logout_redirect_uri=https%3A%2F%2Fw8t.example.com%2Flogin",
		},
		{
			// 部分自建 IdP 没有 end_session_endpoint, 只能清本地登录态
			name:                  "IdP 无登出端点",
			endSessionEndpoint:    "",
			clientID:              "watchalert",
			postLogoutRedirectURI: "https://w8t.example.com/login",
			want:                  "",
		},
		{
			// 未登记回跳地址时跳过去会被 IdP 报错, 因此不跳
			name:                  "未配置回跳地址",
			endSessionEndpoint:    "https://idp.example.com/logout",
			clientID:              "watchalert",
			postLogoutRedirectURI: "",
			want:                  "",
		},
		{
			name:                  "端点自带 query 时用 & 追加",
			endSessionEndpoint:    "https://idp.example.com/logout?tenant=ur",
			clientID:              "watchalert",
			postLogoutRedirectURI: "https://w8t.example.com/login",
			want:                  "https://idp.example.com/logout?tenant=ur&client_id=watchalert&post_logout_redirect_uri=https%3A%2F%2Fw8t.example.com%2Flogin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildLogoutURL(tt.endSessionEndpoint, tt.clientID, tt.postLogoutRedirectURI)
			if got != tt.want {
				t.Errorf("buildLogoutURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
