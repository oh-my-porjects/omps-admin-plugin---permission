package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func roleToResponse(role roleRecord, parentName string) roleResponse {
	resp := roleResponse{
		RoleID:      role.ID,
		Name:        role.Name,
		ParentName:  parentName,
		Status:      role.Status,
		Description: role.Description,
		CreatedAt:   formatTime(role.CreatedAt),
		UpdatedAt:   formatTime(role.UpdatedAt),
		Permissions: []permissionResponse{},
	}
	if role.ParentID != "" {
		parentID := role.ParentID
		resp.ParentID = &parentID
	}
	return resp
}

func permissionToResponse(perm permissionRecord) permissionResponse {
	return permissionResponse{
		PermissionID: perm.ID,
		Code:         perm.Code,
		Name:         perm.Name,
		Description:  perm.Description,
		CreatedAt:    formatTime(perm.CreatedAt),
	}
}

func validName(s string) bool {
	n := runeLen(s)
	return n >= 2 && n <= 30
}

func runeLen(s string) int {
	return len([]rune(s))
}

func validStatus(s string) bool {
	return s == "enabled" || s == "disabled"
}

func validShortID(s string) bool {
	return shortIDRE.MatchString(s)
}

// validUUID 保留旧函数名，兼容平台短 ID 和早期 UUID ID。
func validUUID(s string) bool {
	return validShortID(s) || uuidRE.MatchString(s)
}

func validPermissionCode(s string) bool {
	return permissionCodeRE.MatchString(s)
}

func parsePage(pageRaw, sizeRaw string) (int, int, bool) {
	page, err1 := strconv.Atoi(strings.TrimSpace(pageRaw))
	size, err2 := strconv.Atoi(strings.TrimSpace(sizeRaw))
	if err1 != nil || err2 != nil || page < 1 || size < 1 || size > 100 {
		return 0, 0, false
	}
	return page, size, true
}

func pageBounds(total, page, size int) (int, int) {
	start := (page - 1) * size
	if start > total {
		start = total
	}
	end := start + size
	if end > total {
		end = total
	}
	return start, end
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	return json.NewDecoder(r.Body).Decode(dst)
}

func newShortID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	n := time.Now().UnixNano()
	out := make([]byte, 12)
	for i := 0; i < 12; i++ {
		out[i] = chars[n%62]
		n /= 62
		if n == 0 {
			n = time.Now().UnixNano() + int64(i)
		}
	}
	return string(out)
}

func newUUIDLikeID() string { return newShortID() }

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
