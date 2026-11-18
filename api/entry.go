package api

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/zeromicro/go-zero/core/logc"
	"net/http"
	"watchAlert/pkg/response"
)

func Service(ctx *gin.Context, fu func() (interface{}, interface{})) {
	data, err := fu()
	if err != nil {
		logc.Error(context.Background(), err)
		response.Fail(ctx, err.(error).Error(), "failed")
		ctx.Abort()
		return
	} else {
		response.Success(ctx, data, "success")
	}
}

func BindJson(ctx *gin.Context, req interface{}) {
	err := ctx.ShouldBindJSON(&req)
	if err != nil {
		response.Fail(ctx, err.Error(), "failed")
		ctx.Abort()
		return
	}
}

func BindQuery(ctx *gin.Context, req interface{}) {
	err := ctx.ShouldBindQuery(req)
	if err != nil {
		response.Fail(ctx, err.Error(), "failed")
		ctx.Abort()
		return
	}
}

// BindFormOrQuery 兼容 GET query 与 POST 表单两种参数位置。
// OIDC 回调默认使用 response_mode=query(GET), 但 Azure AD、ADFS 等常配置为
// form_post, 此时 IdP 会以 POST 表单把 code/state 提交到回调地址。
func BindFormOrQuery(ctx *gin.Context, req interface{}) {
	var err error
	if ctx.Request.Method == http.MethodPost {
		err = ctx.ShouldBind(req)
	} else {
		err = ctx.ShouldBindQuery(req)
	}
	if err != nil {
		response.Fail(ctx, err.Error(), "failed")
		ctx.Abort()
		return
	}
}
