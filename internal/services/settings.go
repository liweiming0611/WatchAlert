package services

import (
	"context"
	"watchAlert/config"
	"watchAlert/internal/ctx"
	"watchAlert/internal/models"
	"watchAlert/pkg/ai"
)

type (
	settingService struct {
		ctx *ctx.Context
	}

	InterSettingService interface {
		Save(req interface{}) (interface{}, interface{})
		Get() (interface{}, interface{})
	}
)

func newInterSettingService(ctx *ctx.Context) InterSettingService {
	return settingService{
		ctx: ctx,
	}
}

func (a settingService) Save(req interface{}) (interface{}, interface{}) {
	r := req.(*models.Settings)

	// 设置页不回显客户端密钥, 保存时该字段为空, 直接落库会把已配置的密钥清空,
	// 导致 OIDC 登录整体失效。这里在更新前沿用旧值; 公共客户端(无密钥)本就留空, 不受影响。
	if a.ctx.DB.Setting().Check() && r.OidcConfig.ClientSecret == "" {
		if old, err := a.ctx.DB.Setting().Get(); err == nil {
			r.OidcConfig.ClientSecret = old.OidcConfig.ClientSecret
		}
	}

	if a.ctx.DB.Setting().Check() {
		err := a.ctx.DB.Setting().Update(*r)
		if err != nil {
			return nil, err
		}
	} else {
		err := a.ctx.DB.Setting().Create(*r)
		if err != nil {
			return nil, err
		}
	}

	a.ctx.BackgroundTaskMu.Lock()
	ldapCancel := a.ctx.LdapCancel
	ldapDone := a.ctx.LdapDone
	a.ctx.LdapCancel = nil
	a.ctx.LdapDone = nil
	if ldapCancel != nil {
		ldapCancel()
	}
	a.ctx.BackgroundTaskMu.Unlock()
	if ldapDone != nil {
		<-ldapDone
	}

	if r.AuthType != nil && *r.AuthType == models.SettingLdapAuth {
		c, cancel := context.WithCancel(a.ctx.Ctx)
		done := make(chan struct{})
		a.ctx.BackgroundTaskMu.Lock()
		a.ctx.LdapCancel = cancel
		a.ctx.LdapDone = done
		a.ctx.BackgroundTaskMu.Unlock()
		go func() {
			defer close(done)
			LdapService.SyncUsersCronjob(c, r.LdapConfig)
		}()
	}

	if r.AiConfig.GetEnable() {
		client, err := ai.NewAiClient(&r.AiConfig)
		if err != nil {
			return nil, err
		}
		a.ctx.Redis.ProviderPools().SetClient("AiClient", client)
	}

	return nil, nil
}

func (a settingService) Get() (interface{}, interface{}) {
	get, err := a.ctx.DB.Setting().Get()
	if err != nil {
		return nil, err
	}
	get.AppVersion = config.Version

	return get, nil
}
