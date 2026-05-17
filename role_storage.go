package main

import (
	"context"
	"time"
)

func (p *PermissionPlugin) initStorage(ctx context.Context) error {
	p.ensureMemoryStore()
	if p.db == nil {
		return nil
	}
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS permission_roles (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			name TEXT NOT NULL,
			parent_id TEXT,
			description TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'enabled',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			CONSTRAINT permission_roles_parent_fk FOREIGN KEY (parent_id) REFERENCES permission_roles(id),
			CONSTRAINT permission_roles_no_self_parent CHECK (parent_id IS NULL OR parent_id <> id)
		)`,
		`CREATE TABLE IF NOT EXISTS permission_permissions (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			code TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			description TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS permission_role_permissions (
			id TEXT PRIMARY KEY DEFAULT generate_short_id(),
			role_id TEXT NOT NULL,
			permission_id TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (role_id, permission_id),
			CONSTRAINT permission_role_permissions_role_fk FOREIGN KEY (role_id) REFERENCES permission_roles(id) ON DELETE CASCADE,
			CONSTRAINT permission_role_permissions_permission_fk FOREIGN KEY (permission_id) REFERENCES permission_permissions(id) ON DELETE CASCADE
		)`,
	}
	for _, stmt := range stmts {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	// 加 name / code 业务字段 UNIQUE 索引让 ON CONFLICT (name/code) 可用
	if _, err := p.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_roles_name ON permission_roles(name)`); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_permissions_code ON permission_permissions(code)`); err != nil {
		return err
	}

	// seed system 角色 + 权限：ID 由 generate_short_id() 真随机生成
	// 业务代码用 name / code 字段查找，不依赖硬编码 ID 常量
	seedRoles := []struct {
		name, status, desc, parentName string
	}{
		{"Root", "enabled", "system root role", ""},
		{"Support", "enabled", "bootstrap child role", "Root"},
		{"Disabled Role", "disabled", "bootstrap disabled role", ""},
	}
	for _, sr := range seedRoles {
		if sr.parentName == "" {
			if _, err := p.db.ExecContext(ctx, `
				INSERT INTO permission_roles (name, status, description)
				VALUES ($1, $2, $3) ON CONFLICT (name) DO NOTHING`,
				sr.name, sr.status, sr.desc); err != nil {
				return err
			}
		} else {
			if _, err := p.db.ExecContext(ctx, `
				INSERT INTO permission_roles (name, parent_id, status, description)
				VALUES ($1, (SELECT id FROM permission_roles WHERE name=$2 LIMIT 1), $3, $4)
				ON CONFLICT (name) DO NOTHING`,
				sr.name, sr.parentName, sr.status, sr.desc); err != nil {
				return err
			}
		}
	}

	seedPerms := []struct{ code, name, desc string }{
		{"system.manage", "System Manage", "root management permission"},
		{"users.read", "View Users", "permission intentionally not assigned to root"},
	}
	for _, sp := range seedPerms {
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO permission_permissions (code, name, description)
			VALUES ($1, $2, $3) ON CONFLICT (code) DO NOTHING`, sp.code, sp.name, sp.desc); err != nil {
			return err
		}
	}

	// 角色权限绑定：Root / Support / Disabled Role → system.manage
	for _, roleName := range []string{"Root", "Support", "Disabled Role"} {
		if _, err := p.db.ExecContext(ctx, `
			INSERT INTO permission_role_permissions (role_id, permission_id)
			SELECT r.id, p.id FROM permission_roles r, permission_permissions p
			WHERE r.name = $1 AND p.code = 'system.manage'
			ON CONFLICT (role_id, permission_id) DO NOTHING`, roleName); err != nil {
			return err
		}
	}
	return nil
}

func (p *PermissionPlugin) ensureMemoryStore() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.roles == nil {
		p.roles = map[string]roleRecord{}
	}
	if p.permissions == nil {
		p.permissions = map[string]permissionRecord{}
	}
	if p.rolePerms == nil {
		p.rolePerms = map[string]map[string]bool{}
	}
	if _, exists := p.roles[rootRoleID]; !exists {
		now := time.Now().UTC()
		p.roles[rootRoleID] = roleRecord{ID: rootRoleID, Name: "Root", Status: "enabled", CreatedAt: now, UpdatedAt: now}
		p.permissions[rootPermID] = permissionRecord{ID: rootPermID, Code: "system.manage", Name: "System Manage", CreatedAt: now, UpdatedAt: now}
		p.permissions[unassignedPermID] = permissionRecord{ID: unassignedPermID, Code: "users.read", Name: "View Users", Description: "permission intentionally not assigned to root", CreatedAt: now, UpdatedAt: now}
		p.roles[supportRoleID] = roleRecord{ID: supportRoleID, Name: "Support", ParentID: rootRoleID, Status: "enabled", Description: "bootstrap child role", CreatedAt: now, UpdatedAt: now}
		p.roles[disabledRoleID] = roleRecord{ID: disabledRoleID, Name: "Disabled Role", Status: "disabled", Description: "bootstrap disabled role", CreatedAt: now, UpdatedAt: now}
		p.rolePerms[rootRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[supportRoleID] = map[string]bool{rootPermID: true}
		p.rolePerms[disabledRoleID] = map[string]bool{rootPermID: true}
	}
}
