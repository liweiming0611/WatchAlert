package types

const OidcPassword = "watchAlert"

// RequestOidcCodeQuery 是 IdP 回调参数。
// 除 code/state 外还需要接收 error/error_description: 用户在 IdP 侧取消授权或
// IdP 拒绝请求时回调不带 code, 只带这两个参数。
// 参数位置由 response_mode 决定: 默认在 query(GET), form_post 时在表单(POST)。
type RequestOidcCodeQuery struct {
	Code string `json:"code" form:"code"`
	// State 由服务端在 /api/oidc/authorize 阶段生成并随授权请求下发,
	// 回调时用于取出 PKCE code_verifier 并防止 CSRF(登录会话固定)。
	State            string `json:"state" form:"state"`
	Error            string `json:"error" form:"error"`
	ErrorDescription string `json:"error_description" form:"error_description"`
}

type OidcInfo struct {
	AuthType    *int   `json:"authType"`
	ClientID    string `json:"clientID"`
	UpperURI    string `json:"upperURI"`
	RedirectURI string `json:"redirectURI"`
}

// ResponseOidcLogout 返回退出登录后的跳转地址。
// 非空表示 IdP 提供 end_session_endpoint 且已配置登出回跳地址, 前端应跳转到该地址,
// 由 IdP 一并清理自身会话; 为空则仅回到登录页。
type ResponseOidcLogout struct {
	RedirectURL string `json:"redirectUrl"`
}

type OauthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	// IdToken 部分 IdP 不提供 userinfo 端点, 此时只能从 id_token 的 claims 取用户身份。
	IdToken string `json:"id_token"`
	// IdP 返回的错误信息, 用于把 invalid_grant 等原因透传到日志与页面。
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type RespOpenIDConfiguration struct {
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	Issuer                            string   `json:"issuer"`
	JwksUri                           string   `json:"jwks_uri"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
}

// RespOidcUserInfo 同时承载 userinfo 端点响应与 id_token claims。
// 字段按"标准 OIDC claims + 常见厂商扩展"收集:
// 标准只有 sub 是必返, preferred_username/email 需要对应 scope,
// attributes 为 Casdoor 扩展。
type RespOidcUserInfo struct {
	Attributes struct {
		AvatarUrl   string        `json:"avatar_url"`
		Departments []interface{} `json:"departments"`
		Email       string        `json:"email"`
		Name        string        `json:"name"`
		Nickname    string        `json:"nickname"`
		PhoneNum    string        `json:"phone_num"`
	} `json:"attributes"`
	ClientId string `json:"client_id"`
	Email    string `json:"email"`
	Id       string `json:"id"`
	Sub      string `json:"sub"`

	PreferredUsername string `json:"preferred_username"`
	Username          string `json:"username"`
	Name              string `json:"name"`
	Nickname          string `json:"nickname"`
	Picture           string `json:"picture"`
	PhoneNumber       string `json:"phone_number"`
	EmailVerified     bool   `json:"email_verified"`
}
