package services

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"watchAlert/config"
	"watchAlert/internal/ctx"
	"watchAlert/internal/models"
	"watchAlert/internal/types"
	"watchAlert/pkg/oidc"
	"watchAlert/pkg/tools"

	"github.com/bytedance/sonic"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/zeromicro/go-zero/core/logc"
)

const (
	// oidcStateTTL 是授权上下文的保留时长, 需覆盖用户在 IdP 侧完成登录的最长耗时。
	oidcStateTTL = 10 * time.Minute
	// oidcStateKeyPrefix 是 Redis 中存放授权上下文的 key 前缀。
	oidcStateKeyPrefix = "oidc:state:"
)

// 对外可区分的回调失败原因, 用于回跳登录页时只暴露短码而非内部错误原文。
var (
	ErrOidcSessionExpired = errors.New("OIDC 登录会话不存在或已过期")
	ErrOidcProviderDenied = errors.New("身份提供方拒绝了授权请求")
)

// oidcState 是授权请求与回调之间需要跨请求保留的上下文。
// CodeVerifier 为空表示本次授权未启用 PKCE(机密客户端可关闭, 或 IdP 不支持 S256),
// 此时换取 token 也不得携带 code_verifier。
type oidcState struct {
	CodeVerifier string `json:"codeVerifier"`
	RedirectURI  string `json:"redirectUri"`
}

type oidcService struct {
	ctx *ctx.Context
}

type InterOidcService interface {
	GetOidcInfo() (interface{}, interface{})
	Authorize(ctx *gin.Context) (interface{}, interface{})
	CallBack(ctx *gin.Context, req interface{}) (interface{}, interface{})
	CookieConvertToken(ctx *gin.Context) (interface{}, interface{})
	Logout(ctx *gin.Context) (interface{}, interface{})
}

func newInterOidcService(ctx *ctx.Context) InterOidcService {
	return &oidcService{
		ctx: ctx,
	}
}

func (os oidcService) GetOidcInfo() (interface{}, interface{}) {
	setting, err := os.ctx.DB.Setting().Get()
	if err != nil {
		return nil, err
	}

	return &types.OidcInfo{
		AuthType:    setting.AuthType,
		ClientID:    setting.OidcConfig.ClientID,
		UpperURI:    setting.OidcConfig.UpperURI,
		RedirectURI: setting.OidcConfig.RedirectURI,
	}, nil
}

// Authorize 生成并跳转 OIDC 授权请求。
//
// 授权请求必须由服务端发起: state 与 PKCE 的 code_verifier 需要保存在服务端(Redis),
// 回调换取 token 时才能取回并提交。此前授权 URL 由前端 oidc-client 拼接,
// 该库会自动附加 code_challenge 却把 code_verifier 只留在浏览器 sessionStorage,
// 后端回调拿不到 verifier, IdP 校验失败即返回 invalid_grant。
func (os oidcService) Authorize(ctx *gin.Context) (interface{}, interface{}) {
	setting, err := os.ctx.DB.Setting().Get()
	if err != nil {
		return nil, err
	}

	oidcCfg := setting.OidcConfig
	// 不在这里校验 authType: 登录页只在 authType==2 时展示入口, 而存量实例的
	// authType 可能被保存流程的默认值覆盖, 加硬门禁会让原本可用的实例直接登录不了。
	// 配置完整性校验已足以拦住未配置 OIDC 的场景。
	if oidcCfg.ClientID == "" || oidcCfg.UpperURI == "" || oidcCfg.RedirectURI == "" {
		return nil, fmt.Errorf("OIDC 配置不完整, 请补全认证地址、客户端ID与回调地址")
	}

	cfg, err := oidc.GetOpenIDConfiguration(oidcCfg.UpperURI)
	if err != nil {
		return nil, err
	}
	if cfg.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("OIDC Discovery 未返回 authorization_endpoint, 请检查认证地址")
	}

	// state 作为本次授权会话在 Redis 中的索引, 同时承担 CSRF 防护。
	state, err := oidc.RandomState()
	if err != nil {
		return nil, err
	}

	session := oidcState{RedirectURI: oidcCfg.RedirectURI}
	// IdP 显式声明不支持 S256 时不能硬发 challenge, 否则授权请求会被直接拒绝;
	// 这类 IdP 只支持 plain 或完全不支持 PKCE, 按无 PKCE 处理。
	if oidcCfg.IsPKCEEnable() && oidc.SupportsS256(cfg.CodeChallengeMethodsSupported) {
		if session.CodeVerifier, err = oidc.GenerateVerifier(); err != nil {
			return nil, err
		}
	} else if oidcCfg.IsPKCEEnable() {
		logc.Infof(os.ctx.Ctx, fmt.Sprintf("IdP 未声明支持 S256 PKCE(code_challenge_methods_supported=%v), 本次授权按无 PKCE 处理", cfg.CodeChallengeMethodsSupported))
	}

	raw, err := sonic.Marshal(session)
	if err != nil {
		return nil, err
	}
	if err = os.ctx.Redis.Redis().Set(oidcStateKeyPrefix+state, string(raw), oidcStateTTL).Err(); err != nil {
		return nil, fmt.Errorf("保存 OIDC 登录会话失败: %w", err)
	}

	scope := oidcCfg.Scope
	if scope == "" {
		scope = oidc.DefaultScope
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", oidcCfg.ClientID)
	q.Set("redirect_uri", oidcCfg.RedirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	if session.CodeVerifier != "" {
		q.Set("code_challenge", oidc.S256Challenge(session.CodeVerifier))
		q.Set("code_challenge_method", "S256")
	}

	ctx.Redirect(http.StatusFound, buildAuthorizeURL(cfg.AuthorizationEndpoint, q))

	return nil, nil
}

// buildAuthorizeURL 把查询参数拼到 authorization_endpoint 上, 兼容端点自身已带 query 的情况。
func buildAuthorizeURL(endpoint string, q url.Values) string {
	sep := "?"
	if strings.Contains(endpoint, "?") {
		sep = "&"
	}

	return endpoint + sep + q.Encode()
}

func (os oidcService) CallBack(ctx *gin.Context, req interface{}) (interface{}, interface{}) {
	setting, err := os.ctx.DB.Setting().Get()
	if err != nil {
		return nil, err
	}

	r := req.(*types.RequestOidcCodeQuery)
	// 用户在 IdP 侧取消授权、或 IdP 拒绝请求时, 回调只带 error/error_description 而不带 code。
	if r.Error != "" {
		return nil, fmt.Errorf("%w: %s %s", ErrOidcProviderDenied, r.Error, r.ErrorDescription)
	}
	if r.Code == "" {
		return nil, fmt.Errorf("OIDC 回调缺少 code 参数")
	}

	// 取出并销毁授权上下文: state 不存在说明会话已过期或已被使用, 直接拒绝。
	session, err := os.consumeOidcState(r.State)
	if err != nil {
		return nil, err
	}

	cfg, err := oidc.GetOpenIDConfiguration(setting.OidcConfig.UpperURI)
	if err != nil {
		return nil, err
	}

	authMethod := oidc.ResolveTokenAuthMethod(setting.OidcConfig.TokenAuthMethod,
		cfg.TokenEndpointAuthMethodsSupported, setting.OidcConfig.ClientSecret)

	data, err := oidc.GetOauthToken(cfg.TokenEndpoint, r.Code, session.RedirectURI, session.CodeVerifier,
		setting.OidcConfig.ClientID, setting.OidcConfig.ClientSecret, authMethod)
	if err != nil {
		return nil, err
	}

	identity, err := os.resolveIdentity(cfg, data)
	if err != nil {
		return nil, err
	}

	_, ok, _ := os.ctx.DB.User().Get("", identity.Username, "", "")
	if ok {
		logc.Infof(os.ctx.Ctx, fmt.Sprintf("用户 %s 已存在", identity.Username))
	} else {
		err = os.ctx.DB.User().Create(models.Member{
			UserId:   tools.RandUid(),
			UserName: identity.Username,
			Email:    identity.Email,
			Phone:    identity.Phone,
			Password: tools.GenerateHashPassword(types.OidcPassword),
			CreateBy: "OIDC",
			CreateAt: time.Now().Unix(),
		})
		if err != nil {
			return nil, err
		}
	}

	os.setAuthCookie(ctx, setting.OidcConfig.Domain, data.AccessToken, data.RefreshToken)
	ctx.Redirect(http.StatusTemporaryRedirect, "/")

	return nil, nil
}

// resolveIdentity 按 IdP 实际能力获取用户身份。
// 优先 userinfo 端点(标准做法, 字段最全); 端点缺失、不可用或返回里没有可用标识时,
// 回落到 id_token 的 claims —— Azure AD(部分配置)、自建 IdP 常把 userinfo 关掉,
// 只有 id_token 可用。
func (os oidcService) resolveIdentity(cfg *types.RespOpenIDConfiguration, data *types.OauthToken) (*oidc.UserIdentity, error) {
	if cfg.UserinfoEndpoint != "" {
		info, err := oidc.GetCurrentUser(cfg.UserinfoEndpoint, data.AccessToken)
		if err != nil {
			logc.Errorf(os.ctx.Ctx, "获取 OIDC 用户信息失败, 尝试回落到 id_token: %v", err)
		} else if identity := oidc.ResolveUserIdentity(info); identity.Username != "" {
			return identity, nil
		}
	}

	if data.IdToken != "" {
		claims, err := oidc.ParseIdTokenClaims(data.IdToken)
		if err != nil {
			return nil, err
		}
		if identity := oidc.ResolveUserIdentity(claims); identity.Username != "" {
			return identity, nil
		}
	}

	return nil, fmt.Errorf("身份提供方未返回可用的用户标识, 请确认 scope 包含 openid 及 profile/email")
}

// consumeOidcState 读取并删除 state 对应的授权上下文, 保证一次授权只能兑换一次(防重放)。
func (os oidcService) consumeOidcState(state string) (*oidcState, error) {
	if state == "" {
		return nil, fmt.Errorf("%w, 请重新发起登录", ErrOidcSessionExpired)
	}

	key := oidcStateKeyPrefix + state
	raw, err := os.ctx.Redis.Redis().Get(key).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("%w, 请重新发起登录", ErrOidcSessionExpired)
	}
	if err != nil {
		return nil, fmt.Errorf("读取 OIDC 登录会话失败: %w", err)
	}
	os.ctx.Redis.Redis().Del(key)

	var session oidcState
	if err = sonic.Unmarshal([]byte(raw), &session); err != nil {
		return nil, fmt.Errorf("解析 OIDC 登录会话失败: %w", err)
	}

	return &session, nil
}

// setAuthCookie 写入登录态 cookie。
// httpOnly 避免 XSS 直接读取 token; secure 按实际请求协议动态开启,
// 防止纯 HTTP 部署下 cookie 写不进去。
func (os oidcService) setAuthCookie(ctx *gin.Context, domain, token, refreshToken string) {
	secure := isHTTPS(ctx)

	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("token", token, 60*60*24, "/", domain, secure, true)
	ctx.SetCookie("rftoken", refreshToken, 60*60*24, "/", domain, secure, true)
}

// clearAuthCookie 下发同名空 cookie 使登录态失效。
// cookie 为 httpOnly, 前端无法通过 document.cookie 清除, 必须由服务端下发。
func (os oidcService) clearAuthCookie(ctx *gin.Context, domain string) {
	secure := isHTTPS(ctx)

	ctx.SetSameSite(http.SameSiteLaxMode)
	ctx.SetCookie("token", "", -1, "/", domain, secure, true)
	ctx.SetCookie("rftoken", "", -1, "/", domain, secure, true)
}

// Logout 清除本地登录态, 并在 IdP 提供 end_session_endpoint 时完成 RP-Initiated Logout。
//
// 只清本地 cookie 时 IdP 侧会话仍在, 用户再点登录会被免密直接带回, 表现为"退不出去"。
// 跳转 IdP 登出需要对方登记过登出回跳地址, 因此仅在配置了 PostLogoutRedirectURI 时启用;
// 该跳转的任何前置条件不满足都退化为只清本地登录态, 保证退出动作本身不会失败。
func (os oidcService) Logout(ctx *gin.Context) (interface{}, interface{}) {
	setting, err := os.ctx.DB.Setting().Get()
	if err != nil {
		return nil, err
	}

	oidcCfg := setting.OidcConfig
	os.clearAuthCookie(ctx, oidcCfg.Domain)

	return types.ResponseOidcLogout{RedirectURL: resolveLogoutURL(oidcCfg)}, nil
}

// resolveLogoutURL 在配置与 IdP 能力都具备时给出登出跳转地址, 否则返回空串。
func resolveLogoutURL(oidcCfg models.OidcConfig) string {
	if oidcCfg.PostLogoutRedirectURI == "" || oidcCfg.UpperURI == "" {
		return ""
	}

	cfg, err := oidc.GetOpenIDConfiguration(oidcCfg.UpperURI)
	if err != nil {
		return ""
	}

	return buildLogoutURL(cfg.EndSessionEndpoint, oidcCfg.ClientID, oidcCfg.PostLogoutRedirectURI)
}

// buildLogoutURL 拼接 RP-Initiated Logout 地址。
// IdP 未提供 end_session_endpoint(部分自建实现没有)时返回空串, 退化为只清本地登录态。
func buildLogoutURL(endSessionEndpoint, clientID, postLogoutRedirectURI string) string {
	if endSessionEndpoint == "" || postLogoutRedirectURI == "" {
		return ""
	}

	q := url.Values{}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	q.Set("post_logout_redirect_uri", postLogoutRedirectURI)

	return buildAuthorizeURL(endSessionEndpoint, q)
}

// isHTTPS 判断当前请求是否走 HTTPS: 直连看 TLS, 反向代理看 X-Forwarded-Proto。
func isHTTPS(ctx *gin.Context) bool {
	return ctx.Request.TLS != nil || strings.EqualFold(ctx.GetHeader("X-Forwarded-Proto"), "https")
}

func (os oidcService) CookieConvertToken(ctx *gin.Context) (interface{}, interface{}) {
	setting, err := os.ctx.DB.Setting().Get()
	if err != nil {
		return nil, err
	}

	accessToken, err := ctx.Cookie("token")
	if err != nil {
		return nil, err
	}

	cfg, err := oidc.GetOpenIDConfiguration(setting.OidcConfig.UpperURI)
	if err != nil {
		return nil, err
	}
	if cfg.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("当前 IdP 未提供 userinfo 端点, 无法续期登录态, 请重新登录")
	}

	info, err := oidc.GetCurrentUser(cfg.UserinfoEndpoint, accessToken)
	if err != nil {
		return nil, err
	}

	identity := oidc.ResolveUserIdentity(info)
	if identity.Username == "" {
		return nil, fmt.Errorf("身份提供方未返回可用的用户标识")
	}

	data, _, err := os.ctx.DB.User().Get("", identity.Username, "", "")
	if err != nil {
		return nil, err
	}

	tokenData, err := tools.GenerateToken(data.UserId, data.UserName, data.Password)
	if err != nil {
		return nil, err
	}

	r := &types.RequestUserLogin{
		Identifier: data.UserName,
		Password:   tools.GenerateHashPassword(types.OidcPassword),
	}

	duration := time.Duration(config.Application.Jwt.Expire) * time.Second
	os.ctx.Redis.Redis().Set("uid-"+data.UserId, tools.JsonMarshalToString(r), duration)

	return models.ResponseLoginInfo{
		Token:      tokenData,
		Identifier: data.UserName,
		UserId:     data.UserId,
	}, nil
}
