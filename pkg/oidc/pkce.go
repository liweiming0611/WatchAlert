package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// DefaultScope 是 OIDC 授权请求未显式配置 scope 时使用的默认值。
const DefaultScope = "openid profile email"

// verifierBytes 为 code_verifier 的随机字节数。
// 32 字节经 base64url(无 padding) 编码后为 43 个字符, 满足 RFC 7636 对 43~128 字符的要求。
const verifierBytes = 32

// GenerateVerifier 生成 RFC 7636 定义的 code_verifier。
// 使用 crypto/rand 保证不可预测性, 编码字符集为 base64url(unreserved characters)。
func GenerateVerifier() (string, error) {
	b := make([]byte, verifierBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成 code_verifier 失败: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// S256Challenge 由 code_verifier 推导 code_challenge:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), 结果不带 padding。
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RandomState 生成授权请求的 state 随机串。
// 与 code_verifier 同规格(32 字节 crypto/rand + base64url), 但用途不同, 单独命名避免误读。
func RandomState() (string, error) {
	return GenerateVerifier()
}
