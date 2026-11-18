package oidc

import (
	"encoding/base64"
	"strings"
	"testing"
)

// RFC 7636 Appendix B 给出的官方示例向量。
func TestS256ChallengeRFCVector(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := S256Challenge(verifier); got != want {
		t.Errorf("S256Challenge(%q) = %q, want %q", verifier, got, want)
	}
}

func TestGenerateVerifier(t *testing.T) {
	const (
		minLen = 43
		maxLen = 128
	)

	seen := make(map[string]struct{}, 16)
	for i := 0; i < 16; i++ {
		v, err := GenerateVerifier()
		if err != nil {
			t.Fatalf("GenerateVerifier() error: %v", err)
		}

		if len(v) < minLen || len(v) > maxLen {
			t.Fatalf("verifier 长度 %d 不在 [%d, %d] 区间: %q", len(v), minLen, maxLen, v)
		}

		// 必须可被 base64url 无 padding 解码, 且只含 unreserved 字符。
		if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
			t.Fatalf("verifier %q 不是合法 base64url: %v", v, err)
		}
		if strings.ContainsAny(v, "+/= ") {
			t.Fatalf("verifier %q 含有非 unreserved 字符", v)
		}

		if _, ok := seen[v]; ok {
			t.Fatalf("verifier 出现重复值, 随机源异常: %q", v)
		}
		seen[v] = struct{}{}
	}
}

func TestS256ChallengeDeterministic(t *testing.T) {
	verifier, err := GenerateVerifier()
	if err != nil {
		t.Fatalf("GenerateVerifier() error: %v", err)
	}

	first := S256Challenge(verifier)
	if second := S256Challenge(verifier); first != second {
		t.Fatalf("同一 verifier 两次推导结果不一致: %q vs %q", first, second)
	}
	// SHA256 输出 32 字节, base64url 无 padding 后固定 43 字符。
	if len(first) != 43 {
		t.Fatalf("challenge 长度应为 43, 实际 %d: %q", len(first), first)
	}
	if strings.Contains(first, "=") {
		t.Fatalf("challenge 不应包含 padding: %q", first)
	}
}
