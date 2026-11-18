package models

import "testing"

// TestOidcConfigIsPKCEEnable 覆盖 PKCE 开关的三态语义:
// 老配置没有该字段时为 nil, 必须按开启处理, 否则升级后安全默认会被悄悄破坏。
func TestOidcConfigIsPKCEEnable(t *testing.T) {
	enable := true
	disable := false

	tests := []struct {
		name string
		cfg  OidcConfig
		want bool
	}{
		{"未配置(nil)", OidcConfig{}, true},
		{"显式开启", OidcConfig{PKCEEnable: &enable}, true},
		{"显式关闭", OidcConfig{PKCEEnable: &disable}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.IsPKCEEnable(); got != tt.want {
				t.Errorf("IsPKCEEnable() = %v, want %v", got, tt.want)
			}
		})
	}
}
