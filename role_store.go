package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

type roleListFilter struct {
	ParentID  string
	ParentSet bool
	Status    string
	Keyword   string
	Page      int
	PageSize  int
}

func (p *PermissionPlugin) createRole(ctx context.Context, name, parentID, description, status string) (roleRecord, error) {
	if p.db != nil {
		var role roleRecord
		var parent sql.NullString
		if parentID != "" {
			parent = sql.NullString{String: parentID, Valid: true}
		}
		err := p.db.QueryRowContext(ctx, `
			INSERT INTO permission_roles (name, parent_id, description, status)
			VALUES ($1, $2, $3, $4)
			RETURNING id, name, COALESCE(parent_id, ''), description, status, created_at, updated_at`,
			name, parent, description, status).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt)
		return role, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	role := roleRecord{ID: newUUIDLikeID(), Name: name, ParentID: parentID, Description: description, Status: status, CreatedAt: now, UpdatedAt: now}
	p.roles[role.ID] = role
	return role, nil
}

func (p *PermissionPlugin) updateRole(ctx context.Context, role roleRecord) (roleRecord, error) {
	role.UpdatedAt = time.Now().UTC()
	if p.db != nil {
		var parent sql.NullString
		if role.ParentID != "" {
			parent = sql.NullString{String: role.ParentID, Valid: true}
		}
		err := p.db.QueryRowContext(ctx, `
			UPDATE permission_roles
			SET name=$1, parent_id=$2, description=$3, status=$4, updated_at=now()
			WHERE id=$5
			RETURNING id, name, COALESCE(parent_id, ''), description, status, created_at, updated_at`,
			role.Name, parent, role.Description, role.Status, role.ID).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt)
		return role, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.roles[role.ID] = role
	return role, nil
}

func (p *PermissionPlugin) getRole(ctx context.Context, roleID string) (roleRecord, bool, error) {
	if p.db != nil {
		var role roleRecord
		err := p.db.QueryRowContext(ctx, `
			SELECT id, name, COALESCE(parent_id, ''), description, status, created_at, updated_at
			FROM permission_roles WHERE id=$1`, roleID).Scan(&role.ID, &role.Name, &role.ParentID, &role.Description, &role.Status, &role.CreatedAt, &role.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return roleRecord{}, false, nil
		}
		return role, err == nil, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	role, ok := p.roles[roleID]
	return role, ok, nil
}

func (p *PermissionPlugin) roleExists(ctx context.Context, roleID string) bool {
	_, exists, err := p.getRole(ctx, roleID)
	return err == nil && exists
}

func (p *PermissionPlugin) siblingNameExists(ctx context.Context, excludeRoleID, parentID, name string) bool {
	if p.db != nil {
		var count int
		var err error
		if parentID == "" {
			if excludeRoleID == "" {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM permission_roles WHERE parent_id IS NULL AND name=$1`, name).Scan(&count)
			} else {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM permission_roles WHERE parent_id IS NULL AND name=$1 AND id<>$2`, name, excludeRoleID).Scan(&count)
			}
		} else {
			if excludeRoleID == "" {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM permission_roles WHERE parent_id=$1 AND name=$2`, parentID, name).Scan(&count)
			} else {
				err = p.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM permission_roles WHERE parent_id=$1 AND name=$2 AND id<>$3`, parentID, name, excludeRoleID).Scan(&count)
			}
		}
		return err == nil && count > 0
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, role := range p.roles {
		if role.ID != excludeRoleID && role.ParentID == parentID && role.Name == name {
			return true
		}
	}
	return false
}

func (p *PermissionPlugin) listRoles(ctx context.Context, f roleListFilter) ([]roleResponse, int, error) {
	if p.db != nil {
		where, args := []string{"1=1"}, []any{}
		if f.ParentSet {
			if f.ParentID == "" {
				where = append(where, "r.parent_id IS NULL")
			} else {
				args = append(args, f.ParentID)
				where = append(where, fmt.Sprintf("r.parent_id=$%d", len(args)))
			}
		}
		if f.Status != "" {
			args = append(args, f.Status)
			where = append(where, fmt.Sprintf("r.status=$%d", len(args)))
		}
		if f.Keyword != "" {
			args = append(args, "%"+f.Keyword+"%")
			where = append(where, fmt.Sprintf("r.name ILIKE $%d", len(args)))
		}
		whereSQL := strings.Join(where, " AND ")
		var total int
		if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM permission_roles r WHERE "+whereSQL, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
		rows, err := p.db.QueryContext(ctx, `
			SELECT r.id, r.name, COALESCE(r.parent_id, ''), COALESCE(p.name, ''), r.status, r.description, r.created_at
			FROM permission_roles r
			LEFT JOIN permission_roles p ON p.id = r.parent_id
			WHERE `+whereSQL+`
			ORDER BY r.created_at DESC, r.id
			LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		items := []roleResponse{}
		for rows.Next() {
			var role roleRecord
			var parentName string
			if err := rows.Scan(&role.ID, &role.Name, &role.ParentID, &parentName, &role.Status, &role.Description, &role.CreatedAt); err != nil {
				return nil, 0, err
			}
			items = append(items, roleToResponse(role, parentName))
		}
		return items, total, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	all := make([]roleRecord, 0, len(p.roles))
	for _, role := range p.roles {
		if f.ParentSet && role.ParentID != f.ParentID {
			continue
		}
		if f.Status != "" && role.Status != f.Status {
			continue
		}
		if f.Keyword != "" && !strings.Contains(role.Name, f.Keyword) {
			continue
		}
		all = append(all, role)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	total := len(all)
	start, end := pageBounds(total, f.Page, f.PageSize)
	items := []roleResponse{}
	for _, role := range all[start:end] {
		parentName := ""
		if parent := p.roles[role.ParentID]; parent.ID != "" {
			parentName = parent.Name
		}
		items = append(items, roleToResponse(role, parentName))
	}
	return items, total, nil
}

func (p *PermissionPlugin) roleDetail(ctx context.Context, roleID string) (roleResponse, bool, error) {
	role, exists, err := p.getRole(ctx, roleID)
	if err != nil || !exists {
		return roleResponse{}, exists, err
	}
	parentName := ""
	if role.ParentID != "" {
		if parent, ok, err := p.getRole(ctx, role.ParentID); err == nil && ok {
			parentName = parent.Name
		}
	}
	resp := roleToResponse(role, parentName)
	permissions, err := p.rolePermissions(ctx, roleID)
	if err != nil {
		return roleResponse{}, false, err
	}
	resp.Permissions = permissions
	return resp, true, nil
}

func (p *PermissionPlugin) createPermission(ctx context.Context, code, name, description string) (permissionRecord, error) {
	if p.db != nil {
		var perm permissionRecord
		err := p.db.QueryRowContext(ctx, `
			INSERT INTO permission_permissions (code, name, description)
			VALUES ($1, $2, $3)
			RETURNING id, code, name, description, created_at, updated_at`,
			code, name, description).Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt, &perm.UpdatedAt)
		return perm, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now().UTC()
	perm := permissionRecord{ID: newUUIDLikeID(), Code: code, Name: name, Description: description, CreatedAt: now, UpdatedAt: now}
	p.permissions[perm.ID] = perm
	return perm, nil
}

func (p *PermissionPlugin) permissionCodeExists(ctx context.Context, code string) bool {
	_, exists, err := p.getPermissionByCode(ctx, code)
	return err == nil && exists
}

func (p *PermissionPlugin) getPermissionByCode(ctx context.Context, code string) (permissionRecord, bool, error) {
	if p.db != nil {
		var perm permissionRecord
		err := p.db.QueryRowContext(ctx, `
			SELECT id, code, name, description, created_at, updated_at
			FROM permission_permissions WHERE code=$1`, code).Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt, &perm.UpdatedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return permissionRecord{}, false, nil
		}
		return perm, err == nil, err
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, perm := range p.permissions {
		if perm.Code == code {
			return perm, true, nil
		}
	}
	return permissionRecord{}, false, nil
}

func (p *PermissionPlugin) listPermissions(ctx context.Context, keyword string, page, pageSize int) ([]permissionResponse, int, error) {
	if p.db != nil {
		where := "1=1"
		args := []any{}
		if keyword != "" {
			args = append(args, "%"+keyword+"%")
			where = "(code ILIKE $1 OR name ILIKE $1)"
		}
		var total int
		if err := p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM permission_permissions WHERE "+where, args...).Scan(&total); err != nil {
			return nil, 0, err
		}
		args = append(args, pageSize, (page-1)*pageSize)
		rows, err := p.db.QueryContext(ctx, `
			SELECT id, code, name, description, created_at
			FROM permission_permissions
			WHERE `+where+`
			ORDER BY code
			LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()
		items := []permissionResponse{}
		for rows.Next() {
			var perm permissionRecord
			if err := rows.Scan(&perm.ID, &perm.Code, &perm.Name, &perm.Description, &perm.CreatedAt); err != nil {
				return nil, 0, err
			}
			items = append(items, permissionToResponse(perm))
		}
		return items, total, rows.Err()
	}
	p.ensureMemoryStore()
	p.mu.Lock()
	defer p.mu.Unlock()
	all := make([]permissionRecord, 0, len(p.permissions))
	for _, perm := range p.permissions {
		if keyword == "" || strings.Contains(perm.Code, keyword) || strings.Contains(perm.Name, keyword) {
			all = append(all, perm)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Code < all[j].Code })
	total := len(all)
	start, end := pageBounds(total, page, pageSize)
	items := []permissionResponse{}
	for _, perm := range all[start:end] {
		items = append(items, permissionToResponse(perm))
	}
	return items, total, nil
}
