package models

import (
	"encoding/json"
	"strconv"
)

const (
	SettingSystemAuth = 0
	SettingLdapAuth   = 1
	SettingOidcAuth   = 2
)

type Settings struct {
	IsInit int `json:"isInit"`
	// 0 = 系统认证，1 = LDAP 认证
	AuthType            *int                `json:"authType"`
	AppVersion          string              `json:"appVersion" gorm:"-"`
	CommunicationConfig communicationConfig `json:"communicationConfig" gorm:"communicationConfig;serializer:json"`
	AiConfig            AiConfig            `json:"aiConfig" gorm:"aiConfig;serializer:json"`
	LdapConfig          LdapConfig          `json:"ldapConfig" gorm:"ldapConfig;serializer:json"`
	OidcConfig          OidcConfig          `json:"oidcConfig" gorm:"oidcConfig;serializer:json"`
}

type communicationConfig struct {
	Email emailConfig `json:"email"`
	Phone phoneConfig `json:"phone"`
	SMS   smsConfig   `json:"sms"`
}

type emailConfig struct {
	ServerAddress string `json:"serverAddress"`
	Port          int    `json:"port"`
	Email         string `json:"email"`
	Token         string `json:"token"`
}

// UnmarshalJSON implements custom JSON unmarshaling for emailConfig
func (e *emailConfig) UnmarshalJSON(data []byte) error {
	type Alias emailConfig
	aux := &struct {
		Port interface{} `json:"port"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	switch v := aux.Port.(type) {
	case string:
		if v == "" {
			e.Port = 0
		} else {
			port, err := strconv.Atoi(v)
			if err != nil {
				e.Port = 0
			} else {
				e.Port = port
			}
		}
	case float64:
		e.Port = int(v)
	case int:
		e.Port = v
	default:
		e.Port = 0
	}

	return nil
}

type phoneConfig struct {
	Provider string             `json:"provider"`
	Aliyun   aliyunPhoneConfig  `json:"aliyun"`
	Tencent  tencentPhoneConfig `json:"tencent"`
}

type aliyunPhoneConfig struct {
	AccessKeyId      string `json:"AccessKeyId"`
	AccessKeySecret  string `json:"AccessKeySecret"`
	CalledShowNumber string `json:"CalledShowNumber"`
	TtsCode          string `json:"TtsCode"`
}

type tencentPhoneConfig struct {
	SecretID  string `json:"SecretID"`
	SecretKey string `json:"SecretKey"`
	AppID     string `json:"AppID"`
}

type smsConfig struct {
	Provider string           `json:"provider"`
	Aliyun   aliyunSMSConfig  `json:"aliyun"`
	Tencent  tencentSMSConfig `json:"tencent"`
}

type aliyunSMSConfig struct {
	AccessKeyId     string `json:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret"`
	SignName        string `json:"SignName"`
	TemplateCode    string `json:"TemplateCode"`
}

type tencentSMSConfig struct {
	AppKey     string `json:"AppKey"`
	SdkAppId   string `json:"SdkAppId"`
	TemplateId string `json:"TemplateId"`
	Sign       string `json:"Sign"`
}

// AiConfig ai config
type AiConfig struct {
	Enable *bool `json:"enable"`
	//Type      string `json:"type"` // OpenAi, DeepSeek
	Url       string `json:"url"`
	AppKey    string `json:"appKey"`
	Model     string `json:"model"`
	Timeout   int    `json:"timeout"`
	MaxTokens int    `json:"maxTokens"`
	Prompt    string `json:"prompt"`
}

type LdapConfig struct {
	Address         string `json:"address"`
	BaseDN          string `json:"baseDN"`
	AdminUser       string `json:"adminUser"`
	AdminPass       string `json:"adminPass"`
	DefaultTenant   string `json:"defaultTenant"`
	DefaultUserRole string `json:"defaultUserRole"`
	Cronjob         string `json:"cronjob"`
	// Filter 用于限制允许登录的用户范围，例如: (&(objectClass=person)(memberOf=cn=jms,ou=groups,dc=test,dc=com))
	Filter string `json:"filter"`
}

type OidcConfig struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	UpperURI     string `json:"upperURI"`
	RedirectURI  string `json:"redirectURI"`
	Domain       string `json:"domain"`
	// Scope 授权请求使用的 scope, 为空时回落到 oidc.DefaultScope("openid profile email")。
	Scope string `json:"scope"`
	// TokenAuthMethod 是换 token 时客户端凭据的传递方式。
	// 留空(auto)按 IdP Discovery 声明的 token_endpoint_auth_methods_supported 自动选择:
	// Azure AD / Auth0 / Okta / Google 等要求 client_secret_basic(HTTP Basic),
	// 部分自建 IdP 只接受 client_secret_post(表单参数), 公共客户端为 none。
	TokenAuthMethod string `json:"tokenAuthMethod"`
	// PostLogoutRedirectURI 是 RP-Initiated Logout 完成后 IdP 回跳的地址。
	// 留空表示只清本地登录态、不跳转 IdP 登出端点(部分 IdP 未登记该地址时会报错)。
	PostLogoutRedirectURI string `json:"postLogoutRedirectURI"`
	// PKCEEnable 是否启用 PKCE。使用指针区分"未配置"与"显式关闭":
	// 老配置(无该字段)反序列化后为 nil, 按开启处理, 保证升级后保持安全默认。
	PKCEEnable *bool `json:"pkceEnable"`
}

// IsPKCEEnable 返回是否启用 PKCE, 未显式配置时默认开启。
func (o OidcConfig) IsPKCEEnable() bool {
	return o.PKCEEnable == nil || *o.PKCEEnable
}

func (a AiConfig) GetEnable() bool {
	if a.Enable == nil {
		return false
	}

	return *a.Enable
}
