package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zeromicro/go-zero/core/logc"
	"watchAlert/internal/services"
	"watchAlert/internal/types"
)

type systemController struct{}

var SystemController = new(systemController)

func (systemController systemController) GetOidcInfo(ctx *gin.Context) {
	Service(ctx, func() (interface{}, interface{}) { return services.OidcService.GetOidcInfo() })
}

// Authorize 直接 302 跳转到 IdP 授权端点, 因此不经统一 JSON 响应封装。
func (systemController systemController) Authorize(ctx *gin.Context) {
	if _, err := services.OidcService.Authorize(ctx); err != nil {
		logc.Error(context.Background(), err)
		ctx.Redirect(http.StatusTemporaryRedirect, "/login?oidcError="+oidcErrorCode(err))
	}
}

func (systemController systemController) CallBack(ctx *gin.Context) {
	r := new(types.RequestOidcCodeQuery)
	BindFormOrQuery(ctx, r)
	if ctx.IsAborted() {
		return
	}

	// 回调地址由浏览器直接访问, 失败时回到登录页并带上原因,
	// 而不是让用户只看到一个 {"code":400,...} 的 JSON 页面。
	if _, err := services.OidcService.CallBack(ctx, r); err != nil {
		logc.Error(context.Background(), err)
		ctx.Redirect(http.StatusTemporaryRedirect, "/login?oidcError="+oidcErrorCode(err))
	}
}

// oidcErrorCode 把内部错误收敛为固定短码后再回跳登录页。
// 错误原文含 IdP 地址、HTTP 状态码与 IdP 返回体, 直接拼进 URL 会落到
// 浏览器历史、Referer 与反向代理 access log, 也会把内部拓扑暴露给普通用户。
func oidcErrorCode(err interface{}) string {
	e, ok := err.(error)
	if !ok {
		return "oidc_failed"
	}

	switch {
	case errors.Is(e, services.ErrOidcSessionExpired):
		return "session_expired"
	case errors.Is(e, services.ErrOidcProviderDenied):
		return "access_denied"
	default:
		return "oidc_failed"
	}
}

func (systemController systemController) CookieConvertToken(ctx *gin.Context) {
	Service(ctx, func() (interface{}, interface{}) {
		return services.OidcService.CookieConvertToken(ctx)
	})
}

func (systemController systemController) Logout(ctx *gin.Context) {
	Service(ctx, func() (interface{}, interface{}) {
		return services.OidcService.Logout(ctx)
	})
}
