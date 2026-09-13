package internal

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/oauth"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// systemTokenName is the reserved token name provisioned for internal systems
// per user. Users can disable or delete it from the regular token UI; a
// disabled token means the user does not authorize this internal system, while
// a deleted one is provisioned again on the next internal call.
const systemTokenName = "system"

// internalUserApiKeys resolves a user by their OIDC id (the Casdoor `sub`,
// whether Casdoor is wired through the built-in OIDC provider or as a custom
// OAuth2 provider) and returns that user's dedicated "system" API key:
//
//   - a custom-provider login binding carrying the same provider user id takes
//     precedence, so the key lands on the account the user actually logs in
//     with instead of on a synthetic one
//   - unknown oidc_id: provisions a user account via the same flow as OIDC
//     login registration (no RegisterEnabled gate — the internal key already
//     carries root-level trust)
//   - no "system" token yet: creates one (enabled, unlimited quota, never
//     expires)
//   - token disabled by the user: returns an empty token — the user does not
//     authorize this internal system to use an API key
//
// The token key is returned as stored; callers must prefix it with "sk-".
func internalUserApiKeys(c *gin.Context) {
	oidcId := strings.TrimSpace(c.Query("oidc_id"))
	if oidcId == "" {
		common.ApiErrorI18n(c, i18n.MsgInternalKeyOidcIdRequired)
		return
	}

	user, userCreated, err := resolveOidcUser(oidcId)
	if err != nil {
		common.ApiError(c, err)
		return
	}

	token, tokenCreated, err := getOrCreateSystemToken(user.Id)
	if err != nil {
		common.ApiError(c, err)
		return
	}

	data := gin.H{
		"created_user":  userCreated,
		"created_token": tokenCreated,
		"user": gin.H{
			"id":           user.Id,
			"username":     user.Username,
			"display_name": user.DisplayName,
			"email":        user.Email,
			"oidc_id":      user.OidcId,
			"status":       user.Status,
			"role":         user.Role,
			"group":        user.Group,
			"quota":        user.Quota,
			"used_quota":   user.UsedQuota,
		},
		"token": nil,
	}
	if token.Status != common.TokenStatusDisabled {
		data["token"] = gin.H{
			"id":              token.Id,
			"name":            token.Name,
			"key":             token.Key,
			"status":          token.Status,
			"group":           token.Group,
			"expired_time":    token.ExpiredTime,
			"remain_quota":    token.RemainQuota,
			"unlimited_quota": token.UnlimitedQuota,
			"created_time":    token.CreatedTime,
			"accessed_time":   token.AccessedTime,
		}
	}
	common.SysLog(fmt.Sprintf("[internal] key=%s queried user api-keys: oidc_id=%s user_id=%d user_created=%v token_id=%d token_created=%v",
		c.GetString("internal_key_id"), oidcId, user.Id, userCreated, token.Id, tokenCreated))
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    data,
	})
}

// resolveOidcUser maps an OIDC id (the Casdoor `sub`) to a new-api account:
//
//  1. custom OAuth2 bindings — when Casdoor is wired as a custom provider the
//     login binding lives in user_oauth_bindings (users.oidc_id stays empty
//     there), so the binding is the only link to the account the user logs in
//     with; it wins to keep the system token off a parallel synthetic account
//  2. users.oidc_id — accounts from the built-in OIDC provider or from earlier
//     internal provisioning
//  3. otherwise provision a new account via the OIDC registration flow
//
// A provider_user_id bound to more than one distinct user is ambiguous and
// skipped: issuing the key on a guessed account would be worse than missing
// the binding.
func resolveOidcUser(oidcId string) (*model.User, bool, error) {
	var bindings []*model.UserOAuthBinding
	if err := model.DB.Where("provider_user_id = ?", oidcId).Order("id").Find(&bindings).Error; err != nil {
		return nil, false, err
	}
	distinctUsers := make(map[int]struct{})
	boundUserId := 0
	for _, b := range bindings {
		if _, ok := distinctUsers[b.UserId]; !ok {
			distinctUsers[b.UserId] = struct{}{}
			boundUserId = b.UserId
		}
	}
	if len(distinctUsers) == 1 {
		user := &model.User{}
		if err := model.DB.First(user, boundUserId).Error; err != nil {
			return nil, false, err
		}
		return user, false, nil
	}

	user := &model.User{}
	err := model.DB.Where("oidc_id = ?", oidcId).First(user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		user, err = createOidcUser(oidcId)
		return user, true, err
	}
	if err != nil {
		return nil, false, err
	}
	return user, false, nil
}

// createOidcUser provisions a user account bound to the given OIDC id, keeping
// the built-in-provider branch of findOrCreateOAuthUser (controller/oauth.go)
// as the reference: prefix + next-id username, common role, enabled status,
// and post-creation finalization (sidebar config, new-user quota log).
func createOidcUser(oidcId string) (*model.User, error) {
	provider := &oauth.OIDCProvider{}
	user := &model.User{
		Username:    provider.GetProviderPrefix() + strconv.Itoa(model.GetMaxUserId()+1),
		DisplayName: provider.GetName() + " User",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
	}
	err := model.DB.Transaction(func(tx *gorm.DB) error {
		if err := user.InsertWithTx(tx, 0); err != nil {
			return err
		}
		user.OidcId = oidcId
		return tx.Model(user).Update("oidc_id", oidcId).Error
	})
	if err != nil {
		return nil, err
	}
	user.FinalizeOAuthUserCreation(0)
	return user, nil
}

// getOrCreateSystemToken returns the user's "system" token, creating it on
// first use. Lookup picks the newest match so a stray duplicate (two calls
// racing on creation for the same brand-new user) converges on one token.
func getOrCreateSystemToken(userId int) (*model.Token, bool, error) {
	token := &model.Token{}
	err := model.DB.Where("user_id = ? AND name = ?", userId, systemTokenName).
		Order("id desc").First(token).Error
	if err == nil {
		return token, false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, err
	}
	key, err := common.GenerateKey()
	if err != nil {
		return nil, false, err
	}
	token = &model.Token{
		UserId:         userId,
		Key:            key,
		Name:           systemTokenName,
		Status:         common.TokenStatusEnabled,
		CreatedTime:    common.GetTimestamp(),
		ExpiredTime:    -1,
		UnlimitedQuota: true,
	}
	if err := token.Insert(); err != nil {
		return nil, false, err
	}
	return token, true, nil
}
