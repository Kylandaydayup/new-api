package internal

import (
	"net/http"
	"net/http/httptest"
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
}
