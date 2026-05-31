package main

import (
	"regexp"
	"time"
)

type roleRecord struct {
	ID          string    `json:"role_id"`
	Name        string    `json:"name"`
	ParentID    string    `json:"parent_id,omitempty"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type permissionRecord struct {
	ID          string    `json:"permission_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type roleResponse struct {
	RoleID      string               `json:"role_id"`
	Name        string               `json:"name"`
	ParentID    *string              `json:"parent_id"`
	ParentName  string               `json:"parent_name"`
	Status      string               `json:"status"`
	Description string               `json:"description"`
	CreatedAt   string               `json:"created_at,omitempty"`
	UpdatedAt   string               `json:"updated_at,omitempty"`
	Permissions []permissionResponse `json:"permissions"`
}

type permissionResponse struct {
	PermissionID string `json:"permission_id"`
	Code         string `json:"code"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	CreatedAt    string `json:"created_at,omitempty"`
}

type rolePermissionBindingResponse struct {
	RoleID         string `json:"role_id"`
	RoleName       string `json:"role_name"`
	PermissionID   string `json:"permission_id"`
	PermissionCode string `json:"permission_code"`
	PermissionName string `json:"permission_name"`
	CreatedAt      string `json:"created_at,omitempty"`
}

// 平台短 ID 标准 12 字符 base62, 完整语义名让 UI 前 8 位完全独立可区分
// 跟 role/account 公共模块对齐
const (
	rootRoleID       = "Root00000001"
	rootPermID       = "SysManage001"
	supportRoleID    = "Support00001"
	unassignedPermID = "UsersRead001"
	disabledRoleID   = "Disabled0001"
)

var (
	shortIDRE        = regexp.MustCompile(`^[A-Za-z0-9]{12}$`)
	uuidRE           = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	permissionCodeRE = regexp.MustCompile(`^[a-z0-9._-]{3,80}$`)
)
