package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Tenant represents an organization/customer boundary
type Tenant struct {
	ID        string    `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Domain    string    `json:"domain" db:"domain"`       // e.g., "acme.com"
	Status    string    `json:"status" db:"status"`       // "active", "suspended", "deleted"
	Plan      string    `json:"plan" db:"plan"`           // "starter", "pro", "enterprise"
	MaxAgents int       `json:"max_agents" db:"max_agents"`
	Settings  *TenantSettings `json:"settings,omitempty" db:"settings"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// TenantSettings holds tenant-specific configuration
type TenantSettings struct {
	AllowedIPRanges []string `json:"allowed_ip_ranges,omitempty"`
	MFARequired     bool     `json:"mfa_required"`
	SessionTimeout  int      `json:"session_timeout_minutes"`
	APIRateLimit    int      `json:"api_rate_limit"`
}

// User represents a user account
type User struct {
	ID           string    `json:"id" db:"id"`
	TenantID     string    `json:"tenant_id" db:"tenant_id"`
	Email        string    `json:"email" db:"email"`
	Name         string    `json:"name" db:"name"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Status       string    `json:"status" db:"status"`       // "active", "inactive", "locked"
	MFAEnabled   bool      `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret    string    `json:"-" db:"mfa_secret"`
	LastLogin    *time.Time `json:"last_login,omitempty" db:"last_login"`
	FailedLogins int       `json:"-" db:"failed_logins"`
	LockedUntil  *time.Time `json:"-" db:"locked_until"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// Role represents a set of permissions
type Role struct {
	ID          string       `json:"id" db:"id"`
	TenantID    *string      `json:"tenant_id,omitempty" db:"tenant_id"` // nil for system roles
	Name        string       `json:"name" db:"name"`
	Description string       `json:"description" db:"description"`
	Permissions []Permission `json:"permissions" db:"permissions"`
	IsSystem    bool         `json:"is_system" db:"is_system"` // Built-in vs custom
	CreatedAt   time.Time    `json:"created_at" db:"created_at"`
}

// Permission defines access to a resource
type Permission struct {
	Resource string `json:"resource"` // "agents", "policies", "reports", "*"
	Action   string `json:"action"`   // "read", "write", "delete", "execute", "*"
	Scope    string `json:"scope"`    // "own", "site", "tenant", "global"
}

// UserRole represents the assignment of a role to a user
type UserRole struct {
	UserID    string    `json:"user_id" db:"user_id"`
	RoleID    string    `json:"role_id" db:"role_id"`
	SiteIDs   []string  `json:"site_ids,omitempty" db:"site_ids"` // Empty = all sites
	GrantedBy string    `json:"granted_by" db:"granted_by"`
	GrantedAt time.Time `json:"granted_at" db:"granted_at"`
}

// Site represents a location or network segment within a tenant
type Site struct {
	ID        string    `json:"id" db:"id"`
	TenantID  string    `json:"tenant_id" db:"tenant_id"`
	Name      string    `json:"name" db:"name"`
	Location  string    `json:"location,omitempty" db:"location"`
	Timezone  string    `json:"timezone,omitempty" db:"timezone"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// APIKey represents an API access key
type APIKey struct {
	ID          string     `json:"id" db:"id"`
	TenantID    string     `json:"tenant_id" db:"tenant_id"`
	Name        string     `json:"name" db:"name"`
	KeyHash     string     `json:"-" db:"key_hash"`
	Prefix      string     `json:"prefix" db:"prefix"` // First 8 chars for identification
	Permissions []string   `json:"permissions" db:"permissions"`
	SiteIDs     []string   `json:"site_ids,omitempty" db:"site_ids"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	LastUsed    *time.Time `json:"last_used,omitempty" db:"last_used"`
	CreatedBy   string     `json:"created_by" db:"created_by"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
}

// AgentToken represents an authentication token for an endpoint agent
type AgentToken struct {
	ID        string    `json:"id" db:"id"`
	TenantID  string    `json:"tenant_id" db:"tenant_id"`
	SiteID    string    `json:"site_id" db:"site_id"`
	AgentID   string    `json:"agent_id" db:"agent_id"`
	TokenHash string    `json:"-" db:"token_hash"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty" db:"last_used"`
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	jwt.RegisteredClaims
	UserID      string   `json:"uid"`
	TenantID    string   `json:"tid"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"perms"` // Flattened: "agents:read:tenant"
	SiteIDs     []string `json:"sites"` // Scoped site access (empty = all)
	TokenType   string   `json:"type"`  // "access", "refresh", "agent"
}

// AuditLog represents an audit trail entry
type AuditLog struct {
	ID           string                 `json:"id" db:"id"`
	TenantID     string                 `json:"tenant_id" db:"tenant_id"`
	UserID       *string                `json:"user_id,omitempty" db:"user_id"`
	AgentID      *string                `json:"agent_id,omitempty" db:"agent_id"`
	Action       string                 `json:"action" db:"action"`
	ResourceType string                 `json:"resource_type,omitempty" db:"resource_type"`
	ResourceID   *string                `json:"resource_id,omitempty" db:"resource_id"`
	Details      map[string]interface{} `json:"details,omitempty" db:"details"`
	IPAddress    string                 `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    string                 `json:"user_agent,omitempty" db:"user_agent"`
	Success      bool                   `json:"success" db:"success"`
	ErrorMessage string                 `json:"error_message,omitempty" db:"error_message"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

// Session represents an active user session
type Session struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	TenantID     string    `json:"tenant_id" db:"tenant_id"`
	RefreshToken string    `json:"-" db:"refresh_token"`
	IPAddress    string    `json:"ip_address" db:"ip_address"`
	UserAgent    string    `json:"user_agent" db:"user_agent"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	LastActivity time.Time `json:"last_activity" db:"last_activity"`
}

// Subject status constants
const (
	StatusActive    = "active"
	StatusInactive  = "inactive"
	StatusSuspended = "suspended"
	StatusLocked    = "locked"
	StatusDeleted   = "deleted"
)

// Token type constants
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenTypeAgent   = "agent"
	TokenTypeAPIKey  = "apikey"
)

// Plan constants
const (
	PlanStarter    = "starter"
	PlanPro        = "pro"
	PlanEnterprise = "enterprise"
)

// Default plan limits
var PlanLimits = map[string]int{
	PlanStarter:    25,
	PlanPro:        250,
	PlanEnterprise: 10000,
}
