package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func callUserApiKeys(t *testing.T, oidcId, keyName string) *getUserApiKeysResponse {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	url := "/api/internal/user/api-keys?" + url.Values{"oidc_id": {oidcId}, "key_name": {keyName}}.Encode()
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
	first := callUserApiKeys(t, "casdoor-sub-1", "")
	require.True(t, first.Success, first.Message)
	assert.True(t, first.Data.CreatedUser)
	assert.True(t, first.Data.CreatedToken)
	assert.Equal(t, "casdoor-sub-1", first.Data.User.OidcId)
	assert.Equal(t, common.UserStatusEnabled, first.Data.User.Status)
	assert.Equal(t, common.RoleCommonUser, first.Data.User.Role)
	assert.Equal(t, defaultTokenName, first.Data.Token.Name)
	assert.Equal(t, common.TokenStatusEnabled, first.Data.Token.Status)
	assert.Len(t, first.Data.Token.Key, 48)
	assert.True(t, first.Data.Token.UnlimitedQuota)
	assert.Equal(t, int64(-1), first.Data.Token.ExpiredTime)

	// Second call: returns the very same user and token.
	second := callUserApiKeys(t, "casdoor-sub-1", "")
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

	first := callUserApiKeys(t, "casdoor-sub-2", "")
	require.NotNil(t, first.Data.Token)
	require.NoError(t, model.DB.Model(&model.Token{}).
		Where("id = ?", first.Data.Token.Id).
		Update("status", common.TokenStatusDisabled).Error)

	// Disabled by the user: no key material leaves the system, and the token
	// is not silently re-enabled.
	second := callUserApiKeys(t, "casdoor-sub-2", "")
	require.True(t, second.Success, second.Message)
	assert.False(t, second.Data.CreatedToken)
	assert.Nil(t, second.Data.Token)

	var stored model.Token
	require.NoError(t, model.DB.Where("id = ?", first.Data.Token.Id).First(&stored).Error)
	assert.Equal(t, common.TokenStatusDisabled, stored.Status)
}

func TestInternalUserApiKeysRecreatesDeletedToken(t *testing.T) {
	setupTestDB(t)

	first := callUserApiKeys(t, "casdoor-sub-3", "")
	require.NotNil(t, first.Data.Token)
	deleted := &model.Token{Id: first.Data.Token.Id}
	require.NoError(t, deleted.Delete())

	// Soft-deleted tokens are gone for good; the next call provisions a fresh
	// one instead of resuscitating the deleted key.
	second := callUserApiKeys(t, "casdoor-sub-3", "")
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

	resp := callUserApiKeys(t, "casdoor-sub-4", "")
	require.True(t, resp.Success, resp.Message)
	assert.False(t, resp.Data.CreatedUser)
	assert.Equal(t, existing.Id, resp.Data.User.Id)
	assert.Equal(t, "alice", resp.Data.User.Username)
	require.NotNil(t, resp.Data.Token)
	assert.True(t, resp.Data.CreatedToken)
}

func TestInternalUserApiKeysReusesCustomOAuthBoundUser(t *testing.T) {
	setupTestDB(t)

	// Casdoor wired as a custom OAuth2 provider: the login binding lives in
	// user_oauth_bindings and the real account never gets users.oidc_id set.
	bound := &model.User{
		Username:    "edreamtest03",
		DisplayName: "eDream Test 03",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		AffCode:     "edream03",
	}
	require.NoError(t, model.DB.Create(bound).Error)
	require.NoError(t, model.DB.Create(&model.UserOAuthBinding{
		UserId:         bound.Id,
		ProviderId:     1,
		ProviderUserId: "casdoor-sub-5",
	}).Error)

	resp := callUserApiKeys(t, "casdoor-sub-5", "")
	require.True(t, resp.Success, resp.Message)
	assert.False(t, resp.Data.CreatedUser)
	assert.Equal(t, bound.Id, resp.Data.User.Id)
	assert.Equal(t, "edreamtest03", resp.Data.User.Username)
	// Reused account keeps its binding-only identity; no oidc_id backfill.
	assert.Empty(t, resp.Data.User.OidcId)
	require.NotNil(t, resp.Data.Token)
	assert.True(t, resp.Data.CreatedToken)

	var stored model.Token
	require.NoError(t, model.DB.Where("user_id = ? AND name = ?", bound.Id, defaultTokenName).First(&stored).Error)
}

func TestInternalUserApiKeysPrefersBoundUserOverProvisioned(t *testing.T) {
	setupTestDB(t)

	// Production split-brain shape: an earlier internal call provisioned a
	// synthetic user before the person ever logged in via the custom provider.
	// Once the real binding exists it must win, moving the system token to the
	// account the user actually logs in with.
	synthetic := callUserApiKeys(t, "casdoor-sub-6", "")
	require.True(t, synthetic.Data.CreatedUser)

	real := &model.User{
		Username: "real",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		AffCode:  "real6",
	}
	require.NoError(t, model.DB.Create(real).Error)
	require.NoError(t, model.DB.Create(&model.UserOAuthBinding{
		UserId:         real.Id,
		ProviderId:     1,
		ProviderUserId: "casdoor-sub-6",
	}).Error)

	resp := callUserApiKeys(t, "casdoor-sub-6", "")
	require.True(t, resp.Success, resp.Message)
	assert.False(t, resp.Data.CreatedUser)
	assert.Equal(t, real.Id, resp.Data.User.Id)

	// The system token is issued on the real account, not on the synthetic one.
	var realToken model.Token
	require.NoError(t, model.DB.Where("user_id = ? AND name = ?", real.Id, defaultTokenName).First(&realToken).Error)
	assert.Equal(t, common.TokenStatusEnabled, realToken.Status)
}

func TestInternalUserApiKeysSkipsAmbiguousBindings(t *testing.T) {
	setupTestDB(t)

	// The same provider_user_id bound under two different providers to two
	// different users: the binding cannot identify the account, so resolution
	// must skip it rather than issue the key on a guessed user.
	first := &model.User{Username: "first", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AffCode: "amb1"}
	second := &model.User{Username: "second", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, AffCode: "amb2"}
	require.NoError(t, model.DB.Create(first).Error)
	require.NoError(t, model.DB.Create(second).Error)
	require.NoError(t, model.DB.Create(&model.UserOAuthBinding{UserId: first.Id, ProviderId: 1, ProviderUserId: "casdoor-sub-7"}).Error)
	require.NoError(t, model.DB.Create(&model.UserOAuthBinding{UserId: second.Id, ProviderId: 2, ProviderUserId: "casdoor-sub-7"}).Error)

	resp := callUserApiKeys(t, "casdoor-sub-7", "")
	require.True(t, resp.Success, resp.Message)
	assert.NotEqual(t, first.Id, resp.Data.User.Id)
	assert.NotEqual(t, second.Id, resp.Data.User.Id)
}

func TestInternalUserApiKeysCustomKeyName(t *testing.T) {
	setupTestDB(t)

	first := callUserApiKeys(t, "casdoor-sub-8", "casdoor-portal")
	require.True(t, first.Success, first.Message)
	require.NotNil(t, first.Data.Token)
	assert.True(t, first.Data.CreatedToken)
	assert.Equal(t, "casdoor-portal", first.Data.Token.Name)
	assert.Equal(t, common.TokenStatusEnabled, first.Data.Token.Status)

	// Same key_name returns the same token.
	second := callUserApiKeys(t, "casdoor-sub-8", "casdoor-portal")
	require.True(t, second.Success, second.Message)
	assert.False(t, second.Data.CreatedToken)
	assert.Equal(t, first.Data.Token.Id, second.Data.Token.Id)

	// The default "system" key is a separate, lazily created token; blank and
	// whitespace-only key_name both fall back to it.
	def := callUserApiKeys(t, "casdoor-sub-8", "")
	require.True(t, def.Success, def.Message)
	require.NotNil(t, def.Data.Token)
	assert.Equal(t, defaultTokenName, def.Data.Token.Name)
	assert.NotEqual(t, first.Data.Token.Id, def.Data.Token.Id)

	blank := callUserApiKeys(t, "casdoor-sub-8", "   ")
	require.True(t, blank.Success, blank.Message)
	require.NotNil(t, blank.Data.Token)
	assert.Equal(t, def.Data.Token.Id, blank.Data.Token.Id)
}

func TestInternalUserApiKeysReusesUserCreatedTokenWithSameName(t *testing.T) {
	setupTestDB(t)

	// An existing user-owned token with the requested name is returned as-is
	// instead of creating a parallel token.
	existing := &model.User{
		Username: "bob",
		OidcId:   "casdoor-sub-9",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
	}
	require.NoError(t, model.DB.Create(existing).Error)
	owned := &model.Token{
		UserId:      existing.Id,
		Key:         "user-owned-key",
		Name:        "portal",
		Status:      common.TokenStatusEnabled,
		CreatedTime: common.GetTimestamp(),
		ExpiredTime: -1,
	}
	require.NoError(t, model.DB.Create(owned).Error)

	resp := callUserApiKeys(t, "casdoor-sub-9", "portal")
	require.True(t, resp.Success, resp.Message)
	require.NotNil(t, resp.Data.Token)
	assert.False(t, resp.Data.CreatedToken)
	assert.Equal(t, owned.Id, resp.Data.Token.Id)
	assert.Equal(t, "user-owned-key", resp.Data.Token.Key)
}

func TestInternalUserApiKeysRejectsTooLongKeyName(t *testing.T) {
	setupTestDB(t)

	resp := callUserApiKeys(t, "casdoor-sub-10", strings.Repeat("k", 51))
	require.False(t, resp.Success)
	assert.NotEmpty(t, resp.Message)

	// The request is rejected before any user or token is provisioned.
	var userCount, tokenCount int64
	model.DB.Model(&model.User{}).Count(&userCount)
	model.DB.Model(&model.Token{}).Count(&tokenCount)
	assert.Equal(t, int64(0), userCount)
	assert.Equal(t, int64(0), tokenCount)
}

func TestInternalUserApiKeysRequiresOidcId(t *testing.T) {
	setupTestDB(t)

	resp := callUserApiKeys(t, "", "")
	require.False(t, resp.Success)
	assert.NotEmpty(t, resp.Message)
}
