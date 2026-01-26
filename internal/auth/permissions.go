package auth

import (
	"fmt"
	"strings"
)

// Resource constants
const (
	ResourceAgents         = "agents"
	ResourcePolicies       = "policies"
	ResourceReports        = "reports"
	ResourceEvents         = "events"
	ResourceTelemetry      = "telemetry"
	ResourceUsers          = "users"
	ResourceRoles          = "roles"
	ResourceAPIKeys        = "apikeys"
	ResourceSites          = "sites"
	ResourceTenants        = "tenants"
	ResourceInvestigations = "investigations"
	ResourceSettings       = "settings"
	ResourceAudit          = "audit"
	ResourceAll            = "*"
)

// Action constants
const (
	ActionRead    = "read"
	ActionWrite   = "write"
	ActionDelete  = "delete"
	ActionExecute = "execute"
	ActionAll     = "*"
)

// Scope constants
const (
	ScopeOwn    = "own"    // Only resources owned by the subject
	ScopeSite   = "site"   // Resources within assigned sites
	ScopeTenant = "tenant" // All resources within the tenant
	ScopeGlobal = "global" // All resources across all tenants (superadmin)
)

// SystemRoles defines the built-in roles
var SystemRoles = map[string][]Permission{
	"superadmin": {
		{Resource: ResourceAll, Action: ActionAll, Scope: ScopeGlobal},
	},
	"tenant_admin": {
		{Resource: ResourceAll, Action: ActionAll, Scope: ScopeTenant},
	},
	"security_admin": {
		{Resource: ResourcePolicies, Action: ActionAll, Scope: ScopeTenant},
		{Resource: ResourceAgents, Action: ActionRead, Scope: ScopeTenant},
		{Resource: ResourceAgents, Action: ActionWrite, Scope: ScopeTenant},
		{Resource: ResourceReports, Action: ActionAll, Scope: ScopeTenant},
		{Resource: ResourceEvents, Action: ActionRead, Scope: ScopeTenant},
		{Resource: ResourceSettings, Action: ActionAll, Scope: ScopeTenant},
	},
	"analyst": {
		{Resource: ResourceAgents, Action: ActionRead, Scope: ScopeTenant},
		{Resource: ResourceEvents, Action: ActionRead, Scope: ScopeTenant},
		{Resource: ResourceReports, Action: ActionRead, Scope: ScopeTenant},
		{Resource: ResourceTelemetry, Action: ActionRead, Scope: ScopeTenant},
		{Resource: ResourceInvestigations, Action: ActionAll, Scope: ScopeOwn},
	},
	"viewer": {
		{Resource: ResourceAll, Action: ActionRead, Scope: ScopeTenant},
	},
	"agent": {
		{Resource: ResourceAgents, Action: ActionWrite, Scope: ScopeOwn},
		{Resource: ResourceEvents, Action: ActionWrite, Scope: ScopeOwn},
		{Resource: ResourceTelemetry, Action: ActionWrite, Scope: ScopeOwn},
	},
}

// PermissionEvaluator handles permission checks
type PermissionEvaluator struct{}

// NewPermissionEvaluator creates a new evaluator
func NewPermissionEvaluator() *PermissionEvaluator {
	return &PermissionEvaluator{}
}

// HasPermission checks if the given permissions allow the requested action
func (e *PermissionEvaluator) HasPermission(permissions []string, resource, action string) bool {
	for _, perm := range permissions {
		if e.matchPermission(perm, resource, action) {
			return true
		}
	}
	return false
}

// HasPermissionWithScope checks permission including scope validation
func (e *PermissionEvaluator) HasPermissionWithScope(permissions []string, resource, action, requiredScope string) bool {
	for _, perm := range permissions {
		parts := strings.Split(perm, ":")
		if len(parts) != 3 {
			continue
		}

		permResource, permAction, permScope := parts[0], parts[1], parts[2]

		// Check resource match
		if !e.matchWildcard(permResource, resource) {
			continue
		}

		// Check action match
		if !e.matchWildcard(permAction, action) {
			continue
		}

		// Check scope - higher scopes include lower ones
		if e.scopeIncludes(permScope, requiredScope) {
			return true
		}
	}
	return false
}

// matchPermission checks if a permission string matches resource:action
func (e *PermissionEvaluator) matchPermission(perm, resource, action string) bool {
	parts := strings.Split(perm, ":")
	if len(parts) < 2 {
		return false
	}

	permResource, permAction := parts[0], parts[1]

	return e.matchWildcard(permResource, resource) && e.matchWildcard(permAction, action)
}

// matchWildcard checks if pattern matches target (supports * wildcard)
func (e *PermissionEvaluator) matchWildcard(pattern, target string) bool {
	if pattern == "*" {
		return true
	}
	return strings.EqualFold(pattern, target)
}

// scopeIncludes checks if permScope includes requiredScope
// Hierarchy: global > tenant > site > own
func (e *PermissionEvaluator) scopeIncludes(permScope, requiredScope string) bool {
	scopeHierarchy := map[string]int{
		ScopeOwn:    1,
		ScopeSite:   2,
		ScopeTenant: 3,
		ScopeGlobal: 4,
	}

	permLevel, ok1 := scopeHierarchy[permScope]
	reqLevel, ok2 := scopeHierarchy[requiredScope]

	if !ok1 || !ok2 {
		return false
	}

	return permLevel >= reqLevel
}

// FlattenPermissions converts Permission structs to strings
func FlattenPermissions(permissions []Permission) []string {
	result := make([]string, len(permissions))
	for i, p := range permissions {
		result[i] = fmt.Sprintf("%s:%s:%s", p.Resource, p.Action, p.Scope)
	}
	return result
}

// ParsePermission parses a permission string into a Permission struct
func ParsePermission(s string) (Permission, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 3 {
		return Permission{}, fmt.Errorf("invalid permission format: %s", s)
	}
	return Permission{
		Resource: parts[0],
		Action:   parts[1],
		Scope:    parts[2],
	}, nil
}

// MergePermissions combines multiple permission sets, removing duplicates
func MergePermissions(permSets ...[]string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, perms := range permSets {
		for _, perm := range perms {
			if !seen[perm] {
				seen[perm] = true
				result = append(result, perm)
			}
		}
	}

	return result
}

// GetEffectivePermissions calculates effective permissions from roles
func GetEffectivePermissions(roles []Role) []string {
	var allPerms [][]string
	for _, role := range roles {
		allPerms = append(allPerms, FlattenPermissions(role.Permissions))
	}
	return MergePermissions(allPerms...)
}

// CanAccessResource checks if a subject can access a specific resource instance
func (e *PermissionEvaluator) CanAccessResource(claims *JWTClaims, resource, action, resourceTenantID string, resourceSiteID *string, resourceOwnerID *string) bool {
	// Check basic permission
	if !e.HasPermission(claims.Permissions, resource, action) {
		return false
	}

	// Find the scope for this permission
	var grantedScope string
	for _, perm := range claims.Permissions {
		parts := strings.Split(perm, ":")
		if len(parts) != 3 {
			continue
		}
		if e.matchWildcard(parts[0], resource) && e.matchWildcard(parts[1], action) {
			grantedScope = parts[2]
			break
		}
	}

	switch grantedScope {
	case ScopeGlobal:
		// Can access anything
		return true

	case ScopeTenant:
		// Must be same tenant
		return claims.TenantID == resourceTenantID

	case ScopeSite:
		// Must be same tenant and have access to the site
		if claims.TenantID != resourceTenantID {
			return false
		}
		if resourceSiteID == nil {
			return true // Resource not site-scoped
		}
		if len(claims.SiteIDs) == 0 {
			return true // User has access to all sites
		}
		for _, siteID := range claims.SiteIDs {
			if siteID == *resourceSiteID {
				return true
			}
		}
		return false

	case ScopeOwn:
		// Must be same tenant and own the resource
		if claims.TenantID != resourceTenantID {
			return false
		}
		if resourceOwnerID == nil {
			return false // Can't determine ownership
		}
		return claims.UserID == *resourceOwnerID

	default:
		return false
	}
}

// ValidatePermissionString checks if a permission string is valid
func ValidatePermissionString(perm string) error {
	parts := strings.Split(perm, ":")
	if len(parts) != 3 {
		return fmt.Errorf("permission must have format resource:action:scope, got: %s", perm)
	}

	resource, action, scope := parts[0], parts[1], parts[2]

	// Validate resource
	validResources := map[string]bool{
		ResourceAgents: true, ResourcePolicies: true, ResourceReports: true,
		ResourceEvents: true, ResourceTelemetry: true, ResourceUsers: true,
		ResourceRoles: true, ResourceAPIKeys: true, ResourceSites: true,
		ResourceTenants: true, ResourceInvestigations: true, ResourceSettings: true,
		ResourceAudit: true, ResourceAll: true,
	}
	if !validResources[resource] {
		return fmt.Errorf("invalid resource: %s", resource)
	}

	// Validate action
	validActions := map[string]bool{
		ActionRead: true, ActionWrite: true, ActionDelete: true,
		ActionExecute: true, ActionAll: true,
	}
	if !validActions[action] {
		return fmt.Errorf("invalid action: %s", action)
	}

	// Validate scope
	validScopes := map[string]bool{
		ScopeOwn: true, ScopeSite: true, ScopeTenant: true, ScopeGlobal: true,
	}
	if !validScopes[scope] {
		return fmt.Errorf("invalid scope: %s", scope)
	}

	return nil
}
