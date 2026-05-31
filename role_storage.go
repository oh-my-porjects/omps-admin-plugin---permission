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
		`CREATE OR REPLACE FUNCTION generate_short_id() RETURNS TEXT AS $$
			DECLARE
				chars TEXT := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
				result TEXT := '';
				i INTEGER := 0;
			BEGIN
				FOR i IN 1..12 LOOP
					result := result || substr(chars, floor(random() * length(chars) + 1)::int, 1);
				END LOOP;
				RETURN result;
			END;
		$$ LANGUAGE plpgsql`,
		// Legacy compatibility table. New role data belongs to role.role_roles.
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
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE permission_role_permissions DROP CONSTRAINT IF EXISTS permission_role_permissions_role_fk`); err != nil {
		return err
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
	return p.syncRoleModulePermissionBindings(ctx)
}

func (p *PermissionPlugin) ensureRoleModulePermissionTables(ctx context.Context) bool {
	return p.tableExists(ctx, "role_roles") && p.tableExists(ctx, "role_permissions") && p.tableExists(ctx, "role_role_permissions")
}

func (p *PermissionPlugin) tableExists(ctx context.Context, tableName string) bool {
	if p.db == nil {
		return false
	}
	var exists bool
	err := p.db.QueryRowContext(ctx, "SELECT to_regclass($1) IS NOT NULL", tableName).Scan(&exists)
	return err == nil && exists
}

func (p *PermissionPlugin) roleTableName(ctx context.Context) string {
	if p.db != nil && p.tableExists(ctx, "role_roles") {
		return "role_roles"
	}
	return "permission_roles"
}

func (p *PermissionPlugin) syncRoleModulePermissionBindings(ctx context.Context) error {
	if !p.ensureRoleModulePermissionTables(ctx) {
		return nil
	}
	if _, err := p.db.ExecContext(ctx, `
		INSERT INTO permission_permissions (code, name, description)
		SELECT code, name, description FROM role_permissions
		ON CONFLICT (code) DO NOTHING`); err != nil {
		return err
	}
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO permission_role_permissions (role_id, permission_id)
		SELECT rrp.role_id::text, pp.id
		FROM role_role_permissions rrp
		JOIN role_roles r ON r.id::text = rrp.role_id::text
		JOIN role_permissions rp ON rp.id::text = rrp.permission_id::text
		JOIN permission_permissions pp ON pp.code = rp.code
		WHERE r.name NOT IN ('Root', 'Support', 'Disabled Role')
		ON CONFLICT (role_id, permission_id) DO NOTHING`)
	if err != nil {
		return err
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
	if _, exists := p.permissions[rootPermID]; !exists {
		now := time.Now().UTC()
		p.permissions[rootPermID] = permissionRecord{ID: rootPermID, Code: "system.manage", Name: "System Manage", CreatedAt: now, UpdatedAt: now}
		p.permissions[unassignedPermID] = permissionRecord{ID: unassignedPermID, Code: "users.read", Name: "View Users", Description: "permission intentionally not assigned to root", CreatedAt: now, UpdatedAt: now}
	}
}
