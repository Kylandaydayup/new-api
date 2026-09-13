package internal

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

func TestInternalKeyIpAllowed(t *testing.T) {
	tests := []struct {
		name      string
		whitelist *string
		clientIP  string
		want      bool
	}{
		{"empty whitelist allows any IP", nil, "203.0.113.9", true},
		{"explicit empty whitelist allows any IP", strPtr("  "), "203.0.113.9", true},
		{"localhost matches IPv4 loopback", strPtr("localhost"), "127.0.0.1", true},
		{"localhost matches IPv6 loopback", strPtr("LOCALHOST"), "::1", true},
		{"localhost rejects external IP", strPtr("localhost"), "192.0.2.1", false},
		{"exact IP match", strPtr("10.1.2.3"), "10.1.2.3", true},
		{"exact IP mismatch", strPtr("10.1.2.3"), "10.1.2.4", false},
		{"CIDR contains", strPtr("10.0.0.0/8, 192.168.1.0/24"), "192.168.1.77", true},
		{"CIDR misses", strPtr("10.0.0.0/8"), "11.0.0.1", false},
		{"mixed entries", strPtr("localhost, 10.0.0.0/8"), "::1", true},
		{"unparseable client IP", strPtr("10.0.0.0/8"), "not-an-ip", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			internalKey := &InternalKey{IpWhitelist: tt.whitelist}
			assert.Equal(t, tt.want, internalKey.IpAllowed(tt.clientIP))
		})
	}
}

func TestNormalizeInternalKeyIpWhitelist(t *testing.T) {
	normalized, err := normalizeInternalKeyIpWhitelist(" LocalHost , 10.0.0.0/8 ,10.1.2.3,,localhost")
	require.NoError(t, err)
	assert.Equal(t, "localhost,10.0.0.0/8,10.1.2.3", normalized)

	normalized, err = normalizeInternalKeyIpWhitelist("   ")
	require.NoError(t, err)
	assert.Empty(t, normalized)

	_, err = normalizeInternalKeyIpWhitelist("127.0.0.1, not-a-host")
	assert.Error(t, err)

	_, err = normalizeInternalKeyIpWhitelist("10.0.0.0/99")
	assert.Error(t, err)

	// 规范化后超过列宽 varchar(512) 的输入必须被拒绝，防止依赖数据库各自的超宽行为。
	entries := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		entries = append(entries, fmt.Sprintf("10.%d.0.0/16", i))
	}
	longInput := strings.Join(entries, ",")
	require.Greater(t, len(longInput), internalKeyIpWhitelistMaxLength)
	_, err = normalizeInternalKeyIpWhitelist(longInput)
	require.ErrorIs(t, err, ErrIpWhitelistTooLong)
}

func TestInternalAuthEnforcesIpWhitelist(t *testing.T) {
	setupTestDB(t)
	gin.SetMode(gin.TestMode)

	internalKey := &InternalKey{
		KeyId:       "restricted",
		Key:         "whitelisted-secret-1",
		Name:        "restricted",
		IpWhitelist: strPtr("localhost"),
		Status:      InternalKeyStatusEnabled,
		CreatedTime: common.GetTimestamp(),
	}
	require.NoError(t, internalKey.Insert())

	router := gin.New()
	router.Use(InternalAuth())
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	do := func(remoteAddr string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Key-Id", "restricted")
		req.Header.Set("X-Key", "whitelisted-secret-1")
		router.ServeHTTP(w, req)
		return w
	}

	assert.Equal(t, http.StatusOK, do("127.0.0.1:54321").Code)
	assert.Equal(t, http.StatusOK, do("[::1]:54321").Code)

	forbidden := do("192.0.2.1:54321")
	assert.Equal(t, http.StatusForbidden, forbidden.Code)
	assert.Contains(t, forbidden.Body.String(), `"success":false`)

	// 白名单按 TCP 直连对端判定：伪造的转发头不能让外部地址冒充回环来源。
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-Ip", "127.0.0.1")
	req.Header.Set("X-Key-Id", "restricted")
	req.Header.Set("X-Key", "whitelisted-secret-1")
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
