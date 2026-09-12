package internal

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"

	"github.com/gin-gonic/gin"
)

func getAllInternalKeys(c *gin.Context) {
	keys, err := GetAllInternalKeys()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    keys,
	})
}

func validateInternalKeyName(name string) bool {
	return utf8.RuneCountInString(name) <= 128
}

// normalizeInternalKeyIpWhitelist trims, validates and deduplicates a
// comma-separated whitelist of IPs, CIDR blocks and the "localhost" keyword.
func normalizeInternalKeyIpWhitelist(raw string) (string, error) {
	var entries []string
	seen := make(map[string]bool)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, "localhost") {
			entry = "localhost"
		} else if net.ParseIP(entry) == nil {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return "", err
			}
		}
		if !seen[entry] {
			seen[entry] = true
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, ","), nil
}

func addInternalKey(c *gin.Context) {
	internalKey := InternalKey{}
	if err := c.ShouldBindJSON(&internalKey); err != nil {
		common.ApiError(c, err)
		return
	}
	internalKey.KeyId = strings.TrimSpace(internalKey.KeyId)
	internalKey.Name = strings.TrimSpace(internalKey.Name)
	customKey := strings.TrimSpace(internalKey.Key)
	// 密钥 ID 留空则自动生成，名称作为人工配置的标识。
	if internalKey.KeyId == "" {
		internalKey.KeyId = "key-" + common.GetRandomString(12)
	}
	if !ValidateInternalKeyKeyId(internalKey.KeyId) {
		common.ApiErrorI18n(c, i18n.MsgInternalKeyKeyIdInvalid)
		return
	}
	if !validateInternalKeyName(internalKey.Name) {
		common.ApiErrorI18n(c, i18n.MsgInternalKeyNameTooLong)
		return
	}
	switch {
	case customKey == "":
		customKey = common.GetRandomString(internalKeySecretLength)
	case len(customKey) < internalKeySecretMinLength || len(customKey) > internalKeySecretMaxLength:
		common.ApiErrorI18n(c, i18n.MsgInternalKeyKeyInvalid)
		return
	}
	if internalKey.IpWhitelist != nil {
		normalized, err := normalizeInternalKeyIpWhitelist(*internalKey.IpWhitelist)
		if err != nil {
			common.ApiErrorI18n(c, i18n.MsgInternalKeyIpWhitelistInvalid)
			return
		}
		internalKey.IpWhitelist = &normalized
	}
	exists, err := InternalKeyKeyIdExists(internalKey.KeyId)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	if exists {
		common.ApiErrorI18n(c, i18n.MsgInternalKeyKeyIdDuplicate)
		return
	}
	internalKey.Key = customKey
	internalKey.Id = 0
	// 仅当请求显式携带禁用状态时才以禁用创建，缺省视为启用。
	if internalKey.Status != InternalKeyStatusDisabled {
		internalKey.Status = InternalKeyStatusEnabled
	}
	internalKey.AccessedTime = 0
	internalKey.CreatedTime = common.GetTimestamp()
	if err := internalKey.Insert(); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    internalKey,
	})
}

func updateInternalKey(c *gin.Context) {
	internalKey := InternalKey{}
	if err := c.ShouldBindJSON(&internalKey); err != nil {
		common.ApiError(c, err)
		return
	}
	cleanKey, err := GetInternalKeyById(internalKey.Id)
	if err != nil {
		common.ApiError(c, err)
		return
	}
	name := strings.TrimSpace(internalKey.Name)
	if !validateInternalKeyName(name) {
		common.ApiErrorI18n(c, i18n.MsgInternalKeyNameTooLong)
		return
	}
	newKey := strings.TrimSpace(internalKey.Key)
	if newKey != "" && (len(newKey) < internalKeySecretMinLength || len(newKey) > internalKeySecretMaxLength) {
		common.ApiErrorI18n(c, i18n.MsgInternalKeyKeyInvalid)
		return
	}
	cleanKey.Name = name
	// 0 表示请求未携带状态，保持原状态不变；合法值为启用/禁用两种。
	if internalKey.Status == InternalKeyStatusEnabled || internalKey.Status == InternalKeyStatusDisabled {
		cleanKey.Status = internalKey.Status
	}
	fields := []string{"name", "status"}
	if newKey != "" {
		cleanKey.Key = newKey
		fields = append(fields, "key")
	}
	// nil 表示请求未携带 ip_whitelist，保持原值；携带空串则清空白名单（不限来源）。
	if internalKey.IpWhitelist != nil {
		normalized, err := normalizeInternalKeyIpWhitelist(*internalKey.IpWhitelist)
		if err != nil {
			common.ApiErrorI18n(c, i18n.MsgInternalKeyIpWhitelistInvalid)
			return
		}
		cleanKey.IpWhitelist = &normalized
		fields = append(fields, "ip_whitelist")
	}
	if err := cleanKey.Update(fields...); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data":    cleanKey,
	})
}

func deleteInternalKey(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := DeleteInternalKeyById(id); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
	})
}

// internalAuthCheck is a lightweight endpoint protected by InternalAuth, so
// internal systems can verify their key pair and administrators can confirm a
// pair works.
func internalAuthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "",
		"data": gin.H{
			"key_id": c.GetString("internal_key_id"),
			"name":   c.GetString("internal_key_name"),
		},
	})
}
