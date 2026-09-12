package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// getUserApiKeysResponse mirrors the data payload of internalUserApiKeys.
type getUserApiKeysResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		CreatedUser  bool `json:"created_user"`
		CreatedToken bool `json:"created_token"`
		User         struct {
			Id          int    `json:"id"`
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Email       string `json:"email"`
			OidcId      string `json:"oidc_id"`
			Status      int    `json:"status"`
			Role        int    `json:"role"`
			Group       string `json:"group"`
		} `json:"user"`
		Token *struct {
			Id             int    `json:"id"`
			Name           string `json:"name"`
			Key            string `json:"key"`
			Status         int    `json:"status"`
			ExpiredTime    int64  `json:"expired_time"`
			UnlimitedQuota bool   `json:"unlimited_quota"`
			RemainQuota    int    `json:"remain_quota"`
			Group          string `json:"group"`
			CreatedTime    int64  `json:"created_time"`
			AccessedTime   int64  `json:"accessed_time"`
		} `json:"token"`
	} `json:"data"`
}

func callUserApiKeys(t *testing.T, oidcId string) *getUserApiKeysResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/api/internal/user/api-keys"
	if oidcId != "" {
		url += "?oidc_id=" + oidcId
	}
	c.Request = httptest.NewRequest(http.MethodGet, url, nil)
	c.Set("internal_key_id", "test-system")
	internalUserApiKeys(c)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var resp getUserApiKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return &resp
}

func TestInternalUserApiKeysProvisionsUserAndSystemToken(t *testing.T) {
	setupTestDB(t)

	// First call: provisions both the user (OIDC registration flow) and the
	// dedicated enabled "system" token.
	first := callUserApiKeys(t, "casdoor-sub-1")
	require.True(t, first.Success, first.Message)
	assert.True(t, first.Data.CreatedUser)
	assert.True(t, first.Data.CreatedToken)
	assert.Equal(t, "casdoor-sub-1", first.Data.User.OidcId)
	assert.Equal(t, common.UserStatusEnabled, first.Data.User.Status)
	assert.Equal(t, common.RoleCommonUser, first.Data.User.Role)
	assert.Equal(t, systemTokenName, first.Data.Token.Name)
	assert.Equal(t, common.TokenStatusEnabled, first.Data.Token.Status)
	assert.Len(t, first.Data.Token.Key, 48)
	assert.True(t, first.Data.Token.UnlimitedQuota)
	assert.Equal(t, int64(-1), first.Data.Token.ExpiredTime)

	// Second call: returns the very same user and token.
	second := callUserApiKeys(t, "casdoor-sub-1")
	require.True(t, second.Success, second.Message)
	assert.False(t, second.Data.CreatedUser)
	assert.False(t, second.Data.CreatedToken)
	assert.Equal(t, first.Data.User.Id, second.Data.User.Id)
	require.NotNil(t, second.Data.Token)
	assert.Equal(t, first.Data.Token.Id, second.Data.Token.Id)
	assert.Equal(t, first.Data.Token.Key, second.Data.Token.Key)
}

func TestInternalUserApiKeysDisabledTokenMeansNotAuthorized(t *testing.T) {
	setupTestDB(t)

	first := callUserApiKeys(t, "casdoor-sub-2")
	require.NotNil(t, first.Data.Token)
	require.NoError(t, model.DB.Model(&model.Token{}).
		Where("id = ?", first.Data.Token.Id).
		Update("status", common.TokenStatusDisabled).Error)

	// Disabled by the user: no key material leaves the system, and the token
	// is not silently re-enabled.
	second := callUserApiKeys(t, "casdoor-sub-2")
	require.True(t, second.Success, second.Message)
	assert.False(t, second.Data.CreatedToken)
	assert.Nil(t, second.Data.Token)

	var stored model.Token
	require.NoError(t, model.DB.Where("id = ?", first.Data.Token.Id).First(&stored).Error)
	assert.Equal(t, common.TokenStatusDisabled, stored.Status)
}

func TestInternalUserApiKeysRecreatesDeletedToken(t *testing.T) {
	setupTestDB(t)

	first := callUserApiKeys(t, "casdoor-sub-3")
	require.NotNil(t, first.Data.Token)
	deleted := &model.Token{Id: first.Data.Token.Id}
	require.NoError(t, deleted.Delete())

	// Soft-deleted tokens are gone for good; the next call provisions a fresh
	// one instead of resuscitating the deleted key.
	second := callUserApiKeys(t, "casdoor-sub-3")
	require.True(t, second.Success, second.Message)
	require.NotNil(t, second.Data.Token)
	assert.True(t, second.Data.CreatedToken)
	assert.NotEqual(t, first.Data.Token.Id, second.Data.Token.Id)
	assert.NotEqual(t, first.Data.Token.Key, second.Data.Token.Key)
	assert.Equal(t, common.TokenStatusEnabled, second.Data.Token.Status)
}

func TestInternalUserApiKeysRecognizesExistingUser(t *testing.T) {
	setupTestDB(t)

	existing := &model.User{
		Username: "alice",
		OidcId:   "casdoor-sub-4",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
	}
	require.NoError(t, model.DB.Create(existing).Error)

	resp := callUserApiKeys(t, "casdoor-sub-4")
	require.True(t, resp.Success, resp.Message)
	assert.False(t, resp.Data.CreatedUser)
	assert.Equal(t, existing.Id, resp.Data.User.Id)
	assert.Equal(t, "alice", resp.Data.User.Username)
	require.NotNil(t, resp.Data.Token)
	assert.True(t, resp.Data.CreatedToken)
}

func TestInternalUserApiKeysRequiresOidcId(t *testing.T) {
	setupTestDB(t)

	resp := callUserApiKeys(t, "")
	require.False(t, resp.Success)
	assert.NotEmpty(t, resp.Message)
}
