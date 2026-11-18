package oidc

import (
	"encoding/base64"
	"testing"
	"watchAlert/internal/types"
)

func TestResolveDiscoveryURL(t *testing.T) {
	tests := []struct {
		name   string
		issuer string
		want   string
	}{
		{"issuer 基础地址", "https://idp.example.com", "https://idp.example.com/.well-known/openid-configuration"},
		{"issuer 带末尾斜杠", "https://idp.example.com/", "https://idp.example.com/.well-known/openid-configuration"},
		{"issuer 带路径前缀", "https://idp.example.com/casdoor", "https://idp.example.com/casdoor/.well-known/openid-configuration"},
		{"已是完整 discovery URL", "https://idp.example.com/.well-known/openid-configuration", "https://idp.example.com/.well-known/openid-configuration"},
		{"Azure AD 带租户路径", "https://login.microsoftonline.com/tid/v2.0", "https://login.microsoftonline.com/tid/v2.0/.well-known/openid-configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveDiscoveryURL(tt.issuer); got != tt.want {
				t.Errorf("resolveDiscoveryURL(%q) = %q, want %q", tt.issuer, got, tt.want)
			}
		})
	}
}

func TestResolveTokenAuthMethod(t *testing.T) {
	tests := []struct {
		name         string
		preference   string
		supported    []string
		clientSecret string
		want         string
	}{
		{"显式指定 basic 优先于 IdP 声明", TokenAuthMethodBasic, []string{TokenAuthMethodPost}, "s", TokenAuthMethodBasic},
		{"显式指定 post 优先于 IdP 声明", TokenAuthMethodPost, []string{TokenAuthMethodBasic}, "s", TokenAuthMethodPost},
		{"无密钥时强制 none", "", []string{TokenAuthMethodBasic}, "", TokenAuthMethodNone},
		{"auto 跟随 IdP 首选 basic", "", []string{TokenAuthMethodBasic, TokenAuthMethodPost}, "s", TokenAuthMethodBasic},
		{"auto 跟随 IdP 首选 post", "", []string{TokenAuthMethodPost, TokenAuthMethodBasic}, "s", TokenAuthMethodPost},
		{"IdP 只声明私钥类方式时回落 basic", "", []string{"private_key_jwt"}, "s", TokenAuthMethodBasic},
		{"IdP 未声明时按 OIDC Core 默认 basic", "", nil, "s", TokenAuthMethodBasic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveTokenAuthMethod(tt.preference, tt.supported, tt.clientSecret); got != tt.want {
				t.Errorf("ResolveTokenAuthMethod() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSupportsS256(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		want    bool
	}{
		{"未声明按支持处理", nil, true},
		{"声明支持 S256", []string{"S256"}, true},
		{"声明同时含 plain 与 S256", []string{"plain", "S256"}, true},
		{"大小写不敏感", []string{"s256"}, true},
		{"只声明 plain", []string{"plain"}, false},
		{"声明空数组视为未声明", []string{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SupportsS256(tt.methods); got != tt.want {
				t.Errorf("SupportsS256(%v) = %v, want %v", tt.methods, got, tt.want)
			}
		})
	}
}

func TestResolveUserIdentity(t *testing.T) {
	// Casdoor 把 email/phone 放在 attributes 扩展里, 单独构造避免匿名结构体字面量过长。
	casdoorInfo := &types.RespOidcUserInfo{Id: "u-1"}
	casdoorInfo.Attributes.Email = "casdoor@ur.com"
	casdoorInfo.Attributes.PhoneNum = "13800000000"

	tests := []struct {
		name      string
		info      *types.RespOidcUserInfo
		wantUser  string
		wantEmail string
		wantPhone string
	}{
		{
			name:      "Keycloak 风格 preferred_username",
			info:      &types.RespOidcUserInfo{Sub: "8f14", PreferredUsername: "zhangsan", Email: "z@ur.com", Name: "张三"},
			wantUser:  "zhangsan",
			wantEmail: "z@ur.com",
		},
		{
			name:      "Google 风格只有 email",
			info:      &types.RespOidcUserInfo{Sub: "10293", Email: "lisi@gmail.com", Name: "李四"},
			wantUser:  "lisi@gmail.com",
			wantEmail: "lisi@gmail.com",
		},
		{
			name:      "GitLab 风格 nickname + sub",
			info:      &types.RespOidcUserInfo{Sub: "7", Nickname: "wangwu", Email: "w@ur.com"},
			wantUser:  "w@ur.com",
			wantEmail: "w@ur.com",
		},
		{
			name:     "Azure AD 只有 sub 时回落到 sub",
			info:     &types.RespOidcUserInfo{Sub: "AAAA-1111"},
			wantUser: "AAAA-1111",
		},
		{
			name:      "Casdoor 风格 attributes 扩展",
			info:      casdoorInfo,
			wantUser:  "casdoor@ur.com",
			wantEmail: "casdoor@ur.com",
			wantPhone: "13800000000",
		},
		{
			name:     "无任何标识",
			info:     &types.RespOidcUserInfo{},
			wantUser: "",
		},
		{
			name:     "nil 输入不 panic",
			info:     nil,
			wantUser: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveUserIdentity(tt.info)
			if got.Username != tt.wantUser {
				t.Errorf("Username = %q, want %q", got.Username, tt.wantUser)
			}
			if got.Email != tt.wantEmail {
				t.Errorf("Email = %q, want %q", got.Email, tt.wantEmail)
			}
			if got.Phone != tt.wantPhone {
				t.Errorf("Phone = %q, want %q", got.Phone, tt.wantPhone)
			}
		})
	}
}

func TestParseIdTokenClaims(t *testing.T) {
	// 只构造 payload 部分, 签名段无意义(解析不校验签名)。
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"7","preferred_username":"wangwu","email":"w@ur.com"}`))
	token := "eyJhbGciOiJSUzI1NiJ9." + payload + ".sig"

	claims, err := ParseIdTokenClaims(token)
	if err != nil {
		t.Fatalf("ParseIdTokenClaims() error = %v", err)
	}
	if got := ResolveUserIdentity(claims).Username; got != "wangwu" {
		t.Errorf("Username = %q, want wangwu", got)
	}

	// 带 padding 的 payload 也要能解析(部分 IdP 不按 base64url 无 padding 输出)。
	padded := base64.URLEncoding.EncodeToString([]byte(`{"sub":"9","preferred_username":"padded"}`))
	if _, err := ParseIdTokenClaims("h." + padded + ".s"); err != nil {
		t.Errorf("带 padding 的 id_token 解析失败: %v", err)
	}

	if _, err := ParseIdTokenClaims("not-a-jwt"); err == nil {
		t.Error("非法 id_token 应当返回错误")
	}
}
