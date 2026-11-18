package oidc

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/url"
	"strings"
	"watchAlert/internal/types"
	"watchAlert/pkg/tools"

	"github.com/bytedance/sonic"
)

// wellKnownOidcConfiguration 是 OIDC Discovery 规范定义的标准路径。
const wellKnownOidcConfiguration = "/.well-known/openid-configuration"

// token 端点客户端认证方式。
// 各 IdP 差异极大, 因此以 Discovery 的 token_endpoint_auth_methods_supported 为准:
//   - client_secret_basic: Azure AD / Entra、Auth0、Okta、Google 默认要求 HTTP Basic;
//   - client_secret_post:  部分自建 IdP 只接受表单参数, 同时提交两种会被判为非法请求;
//   - none:               公共客户端(PKCE 场景), 无 client_secret。
const (
	TokenAuthMethodAuto  = "auto"
	TokenAuthMethodBasic = "client_secret_basic"
	TokenAuthMethodPost  = "client_secret_post"
	TokenAuthMethodNone  = "none"
)

func GetOpenIDConfiguration(upper string) (*types.RespOpenIDConfiguration, error) {
	resp, err := tools.Get(nil, resolveDiscoveryURL(upper), 10)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("获取 OIDC Discovery 失败: status=%d, body=%s", resp.StatusCode, truncate(string(body)))
	}

	var d types.RespOpenIDConfiguration
	if err = tools.ParseReaderBody(resp.Body, &d); err != nil {
		return nil, err
	}

	return &d, nil
}

// resolveDiscoveryURL 将 Issuer 基础地址解析为 OIDC Discovery 标准路径。
// 前端 oidc-client 以 Issuer 为 authority 并自动拼接 /.well-known/openid-configuration,
// 这里保持一致; 同时兼容已把完整 discovery URL 存入 UpperURI 的历史配置。
func resolveDiscoveryURL(issuer string) string {
	if strings.HasSuffix(issuer, wellKnownOidcConfiguration) {
		return issuer
	}
	return strings.TrimSuffix(issuer, "/") + wellKnownOidcConfiguration
}

// ResolveTokenAuthMethod 决定换 token 时如何提交客户端凭据。
//
// 优先级: 显式配置 > 无 client_secret 时 none > IdP Discovery 声明的可用方式 >
// OIDC Core 9.1 的默认值 client_secret_basic。
// 注意不能只发 client_secret_post: Azure AD、Auth0、Okta、Google 这类商业 IdP
// 默认只接受 HTTP Basic, 会把 client_id/client_secret 放在表单里的请求判为 invalid_client。
func ResolveTokenAuthMethod(preference string, supported []string, clientSecret string) string {
	switch preference {
	case TokenAuthMethodBasic, TokenAuthMethodPost, TokenAuthMethodNone:
		return preference
	}

	// 公共客户端没有密钥, 只能带 client_id(RFC 6749 4.1.3)。
	if clientSecret == "" {
		return TokenAuthMethodNone
	}

	for _, m := range supported {
		switch m {
		case TokenAuthMethodBasic, TokenAuthMethodPost:
			return m
		}
	}

	return TokenAuthMethodBasic
}

// GetOauthToken 用授权码换取 token。
//
// codeVerifier 为授权请求阶段生成的 PKCE code_verifier: 只要 authorize 请求带了
// code_challenge, 本次请求就必须带对应的 code_verifier, 否则 IdP(如 GitLab)
// 会直接返回 invalid_grant; 反之 authorize 未带 challenge 时该参数必须为空。
// redirectURI 与授权请求中的 redirect_uri 保持一致, 按 RFC 6749 4.1.3 要求回传。
// authMethod 决定客户端凭据放在 Authorization 头还是表单里, 见 ResolveTokenAuthMethod。
func GetOauthToken(tokenUrl, code, redirectURI, codeVerifier, clientID, clientSecret, authMethod string) (*types.OauthToken, error) {
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"

	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", code)
	if redirectURI != "" {
		form.Add("redirect_uri", redirectURI)
	}
	if codeVerifier != "" {
		form.Add("code_verifier", codeVerifier)
	}

	// 客户端凭据只能出现在一处: basic 走 Authorization 头, post 放表单。
	// basic 时不重复在表单里塞 client_id —— RFC 6749 4.1.3 只在"未做客户端认证"时才要求它,
	// 两边同时出现会被部分 IdP(Azure AD 等)判为认证方式冲突。
	switch authMethod {
	case TokenAuthMethodBasic:
		header = tools.MergeHeaders(header, tools.CreateBasicAuthHeader(clientID, clientSecret))
	default:
		form.Add("client_id", clientID)
		if clientSecret != "" {
			form.Add("client_secret", clientSecret)
		}
	}

	resp, err := tools.Post(header, tokenUrl, bytes.NewReader([]byte(form.Encode())), 10)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 一次性读取 body: 失败时也需要把 IdP 返回的 error/error_description 透出,
	// 否则只剩 "empty access_token", 无法区分 PKCE 校验失败与 client 认证失败。
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to get oauth token: read body: %w", err)
	}

	var d types.OauthToken
	if err = sonic.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("failed to get oauth token: status=%d, body=%s, err=%v", resp.StatusCode, truncate(string(body)), err)
	}

	if d.AccessToken == "" {
		return nil, fmt.Errorf("failed to get oauth token: status=%d, error=%s, error_description=%s",
			resp.StatusCode, d.Error, d.ErrorDescription)
	}

	return &d, nil
}

func GetCurrentUser(userInfoUrl, token string) (*types.RespOidcUserInfo, error) {
	header := make(map[string]string)
	header["Authorization"] = "Bearer " + token

	resp, err := tools.Get(header, userInfoUrl, 10)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 非 2xx 时不能当成"字段全空"继续往下走, 否则上层只会看到"用户标识为空"这种误导性错误。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("获取用户信息失败: status=%d, body=%s", resp.StatusCode, truncate(string(body)))
	}

	var d types.RespOidcUserInfo
	if err = tools.ParseReaderBody(resp.Body, &d); err != nil {
		return nil, err
	}

	return &d, nil
}

// UserIdentity 是跨 IdP 归一化后的用户身份。
// 不同 IdP 返回的字段差异很大: 标准 OIDC 只强制 sub, Keycloak/Azure 给
// preferred_username, Google 只给 email, Casdoor 额外给 id 与 attributes。
// 登录标识必须取"稳定且可读"的那个, 否则会出现空用户名或每次登录新建用户。
type UserIdentity struct {
	Username string
	Email    string
	Phone    string
	Name     string
	Avatar   string
}

// ResolveUserIdentity 按可用性依次回落到各 IdP 常见字段, 返回归一化身份。
// 顺序: preferred_username > username > email > sub > id > name。
// 不用 sub 作为首选: 它虽稳定但通常不可读(如 GitLab 的用户 ID 数字串),
// 会污染 WatchAlert 的用户名列表与审计记录。
func ResolveUserIdentity(info *types.RespOidcUserInfo) *UserIdentity {
	if info == nil {
		return &UserIdentity{}
	}

	identity := &UserIdentity{
		Email:  strings.TrimSpace(firstNonEmpty(info.Email, info.Attributes.Email)),
		Phone:  strings.TrimSpace(firstNonEmpty(info.PhoneNumber, info.Attributes.PhoneNum)),
		Name:   strings.TrimSpace(firstNonEmpty(info.Name, info.Nickname, info.Attributes.Name, info.Attributes.Nickname)),
		Avatar: strings.TrimSpace(firstNonEmpty(info.Picture, info.Attributes.AvatarUrl)),
	}

	identity.Username = strings.TrimSpace(firstNonEmpty(
		info.PreferredUsername,
		info.Username,
		identity.Email,
		info.Sub,
		info.Id,
		identity.Name,
	))

	return identity
}

// ParseIdTokenClaims 从 id_token 中解析 claims, 用于 IdP 未提供 userinfo 端点时的身份兜底。
// 该 token 由服务端直连 token 端点取得(非浏览器中转), 按 OIDC Core 3.1.3.7 属可信来源,
// 因此这里只解析 payload 而不校验签名 —— 不得用于任何需要密码学保证的判断。
func ParseIdTokenClaims(idToken string) (*types.RespOidcUserInfo, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("id_token 格式非法, 无法解析用户身份")
	}

	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("解析 id_token payload 失败: %w", err)
	}

	var claims types.RespOidcUserInfo
	if err = sonic.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("解析 id_token claims 失败: %w", err)
	}

	return &claims, nil
}

// SupportsS256 判断 IdP 是否声明支持 S256 的 PKCE。
// 未声明(code_challenge_methods_supported 为空)时按支持处理, 保持 PKCE 默认开启。
func SupportsS256(methods []string) bool {
	if len(methods) == 0 {
		return true
	}

	for _, m := range methods {
		if strings.EqualFold(m, "S256") {
			return true
		}
	}

	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return ""
}

// truncate 限制错误信息中 body 的长度, 避免日志被大响应体撑爆。
func truncate(s string) string {
	const maxLen = 512
	if len(s) <= maxLen {
		return s
	}

	return s[:maxLen] + "...(truncated)"
}
