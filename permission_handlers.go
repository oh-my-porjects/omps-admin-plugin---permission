package main

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (p *PermissionPlugin) permissionsExist(ctx context.Context, ids []string) bool {
	if len(ids) == 0 {
		return true
	}
	if p.db != nil {
		for _, id := range ids {
			var exists bool
			if err := p.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM permission_permissions WHERE id=$1)", id).Scan(&exists); err != nil || !exists {
				return false
			}
		}
		return true
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, id := range ids {
		if _, ok := p.permissions[id]; !ok {
			return false
		}
	}
	return true
}

func (p *PermissionPlugin) assignPermissions(ctx context.Context, roleID string, permissionIDs []string) (time.Time, error) {
	now := time.Now().UTC()
	if p.db != nil {
		roleTable := p.roleTableName(ctx)
		tx, err := p.db.BeginTx(ctx, nil)
		if err != nil {
			return time.Time{}, err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, "DELETE FROM permission_role_permissions WHERE role_id=$1", roleID); err != nil {
			return time.Time{}, err
		}
		for _, permissionID := range permissionIDs {
			if _, err := tx.ExecContext(ctx, "INSERT INTO permission_role_permissions (role_id, permission_id) VALUES ($1, $2)", roleID, permissionID); err != nil {
				return time.Time{}, err
			}
		}
		if err := tx.QueryRowContext(ctx, "UPDATE "+roleTable+" SET updated_at=now() WHERE id::text=$1 RETURNING updated_at", roleID).Scan(&now); err != nil {
			return time.Time{}, err
		}
		return now, tx.Commit()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	set := map[string]bool{}
	for _, id := range permissionIDs {
		set[id] = true
	}
	p.rolePerms[roleID] = set
	role := p.roles[roleID]
	role.UpdatedAt = now
	p.roles[roleID] = role
	return now, nil
}

func (p *PermissionPlugin) permissionSet(ctx context.Context, roleID string) (map[string]bool, error) {
	set := map[string]bool{}
	if roleID == "" {
		return nil, nil
	}
	if p.db != nil {
		rows, err := p.db.QueryContext(ctx, "SELECT permission_id FROM permission_role_permissions WHERE role_id=$1", roleID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			set[id] = true
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		if p.ensureRoleModulePermissionTables(ctx) {
			roleRows, err := p.db.QueryContext(ctx, `
				SELECT pp.id
				FROM role_role_permissions rrp
				JOIN role_permissions rp ON rp.id::text = rrp.permission_id::text
				JOIN permission_permissions pp ON pp.code = rp.code
				WHERE rrp.role_id::text=$1`, roleID)
			if err != nil {
				return nil, err
			}
			defer roleRows.Close()
			for roleRows.Next() {
				var id string
				if err := roleRows.Scan(&id); err != nil {
					return nil, err
				}
				set[id] = true
			}
			if err := roleRows.Err(); err != nil {
				return nil, err
			}
		}
		return set, nil
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for id := range p.rolePerms[roleID] {
		set[id] = true
	}
	return set, nil
}

func (p *PermissionPlugin) rolePermissions(ctx context.Context, roleID string) ([]permissionResponse, error) {
	if p.db != nil {
		rawSQL := `
			SELECT rp.permission_id, p.code, p.name, p.description, p.created_at, 0 AS source_rank
			FROM permission_role_permissions rp
			JOIN permission_permissions p ON p.id = rp.permission_id
			WHERE rp.role_id=$1`
		if p.ensureRoleModulePermissionTables(ctx) {
			rawSQL += `
			UNION ALL
			SELECT COALESCE(pp.id, rp.id::text), rp.code, rp.name, rp.description, rp.created_at, 1 AS source_rank
			FROM role_role_permissions rrp
			JOIN role_permissions rp ON rp.id::text = rrp.permission_id::text
			LEFT JOIN permission_permissions pp ON pp.code = rp.code
			WHERE rrp.role_id::text=$1`
		}
		rows, err := p.db.QueryContext(ctx, `
			WITH raw_permissions AS (`+rawSQL+`),
			permissions AS (
				SELECT DISTINCT ON (code) permission_id, code, name, description, created_at
				FROM raw_permissions
				ORDER BY code, source_rank, created_at
			)
			SELECT permission_id, code, name, description, created_at
			FROM permissions
			ORDER BY code`, roleID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		items := []permissionResponse{}
		for rows.Next() {
			var perm permissionRecord
			if err := rows.Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt); err != nil {
				return nil, err
			}
			items = append(items, permissionToResponse(perm))
		}
		return items, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	ids := sortedKeys(p.rolePerms[roleID])
	items := []permissionResponse{}
	for _, id := range ids {
		if perm, ok := p.permissions[id]; ok {
			items = append(items, permissionToResponse(perm))
		}
	}
	return items, nil
}

func (p *PermissionPlugin) listRolePermissionBindings(ctx context.Context, roleID string, page, pageSize int) ([]rolePermissionBindingResponse, int, error) {
	if p.db != nil {
		roleTable := p.roleTableName(ctx)
		rawSQL := `
			SELECT rp.role_id, rp.permission_id, p.code AS permission_code, p.name AS permission_name, rp.created_at, 0 AS source_rank
			FROM permission_role_permissions rp
			JOIN permission_permissions p ON p.id = rp.permission_id`
		if p.ensureRoleModulePermissionTables(ctx) {
			rawSQL += `
			UNION ALL
			SELECT rrp.role_id::text, COALESCE(pp.id, rp.id::text), rp.code, rp.name, rrp.created_at, 1 AS source_rank
			FROM role_role_permissions rrp
			JOIN role_permissions rp ON rp.id::text = rrp.permission_id::text
			LEFT JOIN permission_permissions pp ON pp.code = rp.code`
		}
		where := []string{"1=1"}
		args := []any{}
		if roleID != "" {
			args = append(args, roleID)
			where = append(where, "b.role_id=$1")
		}
		if roleTable == "role_roles" {
			where = append(where, "r.name NOT IN ('Root', 'Support', 'Disabled Role')")
		}
		whereSQL := "WHERE " + strings.Join(where, " AND ")
		cteSQL := `
			WITH raw_bindings AS (` + rawSQL + `),
			bindings AS (
				SELECT DISTINCT ON (role_id, permission_code)
					role_id, permission_id, permission_code, permission_name, created_at
				FROM raw_bindings
				ORDER BY role_id, permission_code, source_rank, created_at
			)`
		var total int
		if err := p.db.QueryRowContext(ctx, cteSQL+`
			SELECT COUNT(*)
			FROM bindings b
			JOIN `+roleTable+` r ON r.id::text = b.role_id
			`+whereSQL, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, pageSize, (page-1)*pageSize)
		rows, err := p.db.QueryContext(ctx, cteSQL+`
			SELECT b.role_id, r.name, b.permission_id, b.permission_code, b.permission_name, b.created_at
			FROM bindings b
			JOIN `+roleTable+` r ON r.id::text = b.role_id
			`+whereSQL+`
			ORDER BY r.name, b.permission_code
			LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		items := []rolePermissionBindingResponse{}
		for rows.Next() {
			var item rolePermissionBindingResponse
			var createdAt time.Time
			if err := rows.Scan(&item.RoleID, &item.RoleName, &item.PermissionID, &item.PermissionCode, &item.PermissionName, &createdAt); err != nil {
				return nil, 0, err
			}
			item.CreatedAt = formatTime(createdAt)
			items = append(items, item)
		}
		return items, total, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	items := []rolePermissionBindingResponse{}
	for rid, set := range p.rolePerms {
		if roleID != "" && rid != roleID {
			continue
		}
		role := p.roles[rid]
		for pid := range set {
			perm, ok := p.permissions[pid]
			if !ok {
				continue
			}
			items = append(items, rolePermissionBindingResponse{
				RoleID:         rid,
				RoleName:       role.Name,
				PermissionID:   pid,
				PermissionCode: perm.Code,
				PermissionName: perm.Name,
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].RoleName == items[j].RoleName {
			return items[i].PermissionCode < items[j].PermissionCode
		}
		return items[i].RoleName < items[j].RoleName
	})
	total := len(items)
	start, end := pageBounds(total, page, pageSize)
	return items[start:end], total, nil
}

func (p *PermissionPlugin) rolePermissionsWithinParent(ctx context.Context, roleID, parentID string) (bool, error) {
	parentSet, err := p.permissionSet(ctx, parentID)
	if err != nil {
		return false, err
	}
	roleSet, err := p.permissionSet(ctx, roleID)
	if err != nil {
		return false, err
	}
	return permissionSetWithin(parentSet, roleSet), nil
}

func (p *PermissionPlugin) childrenWithinPermissionSet(ctx context.Context, roleID string, parentSet map[string]bool) (bool, error) {
	children, err := p.childRoleIDs(ctx, roleID)
	if err != nil {
		return false, err
	}
	for _, childID := range children {
		childSet, err := p.permissionSet(ctx, childID)
		if err != nil {
			return false, err
		}
		if !permissionSetWithin(parentSet, childSet) {
			return false, nil
		}
	}
	return true, nil
}

func (p *PermissionPlugin) childRoleIDs(ctx context.Context, roleID string) ([]string, error) {
	if p.db != nil {
		roleTable := p.roleTableName(ctx)
		rows, err := p.db.QueryContext(ctx, "SELECT id::text FROM "+roleTable+" WHERE parent_id::text=$1", roleID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for _, role := range p.roles {
		if role.ParentID == roleID {
			ids = append(ids, role.ID)
		}
	}
	return ids, nil
}

func (p *PermissionPlugin) wouldCreateCycle(ctx context.Context, roleID, parentID string) bool {
	for current := parentID; current != ""; {
		if current == roleID {
			return true
		}
		parent, exists, err := p.getRole(ctx, current)
		if err != nil || !exists {
			return false
		}
		current = parent.ParentID
	}
	return false
}

func (p *PermissionPlugin) roleDirectlyHasPermission(ctx context.Context, roleID, permissionID string) bool {
	if p.db != nil {
		var exists bool
		err := p.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM permission_role_permissions WHERE role_id=$1 AND permission_id=$2)", roleID, permissionID).Scan(&exists)
		if err != nil || exists {
			return err == nil && exists
		}
		if !p.ensureRoleModulePermissionTables(ctx) {
			return false
		}
		err = p.db.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM role_role_permissions rrp
				JOIN role_permissions rp ON rp.id::text = rrp.permission_id::text
				JOIN permission_permissions pp ON pp.code = rp.code
				WHERE rrp.role_id::text=$1 AND pp.id=$2
			)`, roleID, permissionID).Scan(&exists)
		return err == nil && exists
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.rolePerms[roleID][permissionID]
}

func permissionSetWithin(parentSet map[string]bool, childSet map[string]bool) bool {
	if parentSet == nil {
		return true
	}
	for id := range childSet {
		if !parentSet[id] {
			return false
		}
	}
	return true
}
