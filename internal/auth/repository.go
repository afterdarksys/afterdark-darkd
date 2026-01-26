package auth

import (
	"context"
	"errors"
	"time"
)

// Repository errors
var (
	ErrNotFound        = errors.New("resource not found")
	ErrDuplicateEmail  = errors.New("email already exists")
	ErrDuplicateDomain = errors.New("domain already exists")
	ErrDuplicateName   = errors.New("name already exists")
	ErrInvalidTenant   = errors.New("invalid tenant")
	ErrTenantRequired  = errors.New("tenant ID required")
)

// TenantRepository defines tenant data access operations
type TenantRepository interface {
	// Create creates a new tenant
	Create(ctx context.Context, tenant *Tenant) error

	// GetByID retrieves a tenant by ID
	GetByID(ctx context.Context, id string) (*Tenant, error)

	// GetByDomain retrieves a tenant by domain
	GetByDomain(ctx context.Context, domain string) (*Tenant, error)

	// Update updates a tenant
	Update(ctx context.Context, tenant *Tenant) error

	// Delete soft-deletes a tenant
	Delete(ctx context.Context, id string) error

	// List retrieves all tenants with optional filtering
	List(ctx context.Context, filter *TenantFilter) ([]*Tenant, error)

	// CountAgents returns the number of agents for a tenant
	CountAgents(ctx context.Context, tenantID string) (int, error)
}

// TenantFilter holds filtering options for listing tenants
type TenantFilter struct {
	Status  string
	Plan    string
	Limit   int
	Offset  int
	OrderBy string
}

// UserRepository defines user data access operations
type UserRepository interface {
	// Create creates a new user
	Create(ctx context.Context, user *User) error

	// GetByID retrieves a user by ID
	GetByID(ctx context.Context, id string) (*User, error)

	// GetByEmail retrieves a user by email within a tenant
	GetByEmail(ctx context.Context, tenantID, email string) (*User, error)

	// Update updates a user
	Update(ctx context.Context, user *User) error

	// Delete soft-deletes a user
	Delete(ctx context.Context, id string) error

	// List retrieves users for a tenant
	List(ctx context.Context, tenantID string, filter *UserFilter) ([]*User, error)

	// UpdateLastLogin updates the user's last login timestamp
	UpdateLastLogin(ctx context.Context, id string) error

	// IncrementFailedLogins increments the failed login counter
	IncrementFailedLogins(ctx context.Context, id string) error

	// ResetFailedLogins resets the failed login counter
	ResetFailedLogins(ctx context.Context, id string) error

	// LockUser locks a user account until the specified time
	LockUser(ctx context.Context, id string, until time.Time) error

	// UnlockUser unlocks a user account
	UnlockUser(ctx context.Context, id string) error
}

// UserFilter holds filtering options for listing users
type UserFilter struct {
	Status  string
	SiteID  string
	Search  string
	Limit   int
	Offset  int
	OrderBy string
}

// RoleRepository defines role data access operations
type RoleRepository interface {
	// Create creates a new role
	Create(ctx context.Context, role *Role) error

	// GetByID retrieves a role by ID
	GetByID(ctx context.Context, id string) (*Role, error)

	// GetByName retrieves a role by name within a tenant (or system role if tenantID is empty)
	GetByName(ctx context.Context, tenantID, name string) (*Role, error)

	// Update updates a role (cannot update system roles)
	Update(ctx context.Context, role *Role) error

	// Delete deletes a role (cannot delete system roles)
	Delete(ctx context.Context, id string) error

	// List retrieves roles for a tenant (including system roles)
	List(ctx context.Context, tenantID string) ([]*Role, error)

	// GetSystemRoles retrieves all system roles
	GetSystemRoles(ctx context.Context) ([]*Role, error)

	// GetUserRoles retrieves all roles assigned to a user
	GetUserRoles(ctx context.Context, userID string) ([]*Role, error)

	// AssignRole assigns a role to a user
	AssignRole(ctx context.Context, assignment *UserRole) error

	// RevokeRole removes a role from a user
	RevokeRole(ctx context.Context, userID, roleID string) error

	// GetUserPermissions calculates effective permissions for a user
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)
}

// SiteRepository defines site data access operations
type SiteRepository interface {
	// Create creates a new site
	Create(ctx context.Context, site *Site) error

	// GetByID retrieves a site by ID
	GetByID(ctx context.Context, id string) (*Site, error)

	// Update updates a site
	Update(ctx context.Context, site *Site) error

	// Delete deletes a site
	Delete(ctx context.Context, id string) error

	// List retrieves sites for a tenant
	List(ctx context.Context, tenantID string) ([]*Site, error)
}

// APIKeyRepository defines API key data access operations
type APIKeyRepository interface {
	// Create creates a new API key
	Create(ctx context.Context, key *APIKey) error

	// GetByID retrieves an API key by ID
	GetByID(ctx context.Context, id string) (*APIKey, error)

	// GetByPrefix retrieves an API key by its prefix
	GetByPrefix(ctx context.Context, prefix string) (*APIKey, error)

	// ValidateKey validates an API key and returns the full key record
	ValidateKey(ctx context.Context, keyString string) (*APIKey, error)

	// UpdateLastUsed updates the last used timestamp
	UpdateLastUsed(ctx context.Context, id string) error

	// Revoke revokes an API key
	Revoke(ctx context.Context, id string) error

	// List retrieves API keys for a tenant
	List(ctx context.Context, tenantID string) ([]*APIKey, error)

	// ListByUser retrieves API keys created by a user
	ListByUser(ctx context.Context, userID string) ([]*APIKey, error)

	// DeleteExpired deletes expired API keys
	DeleteExpired(ctx context.Context) (int, error)
}

// AgentTokenRepository defines agent token data access operations
type AgentTokenRepository interface {
	// Create creates a new agent token
	Create(ctx context.Context, token *AgentToken) error

	// GetByAgentID retrieves a token by agent ID
	GetByAgentID(ctx context.Context, agentID string) (*AgentToken, error)

	// ValidateToken validates an agent token
	ValidateToken(ctx context.Context, agentID, tokenString string) (*AgentToken, error)

	// UpdateLastUsed updates the last used timestamp
	UpdateLastUsed(ctx context.Context, id string) error

	// Rotate creates a new token for an agent, invalidating the old one
	Rotate(ctx context.Context, agentID string, newToken *AgentToken) error

	// Delete deletes an agent token
	Delete(ctx context.Context, agentID string) error

	// List retrieves agent tokens for a tenant
	List(ctx context.Context, tenantID string) ([]*AgentToken, error)

	// DeleteExpired deletes expired tokens
	DeleteExpired(ctx context.Context) (int, error)
}

// SessionRepository defines session data access operations
type SessionRepository interface {
	// Create creates a new session
	Create(ctx context.Context, session *Session) error

	// GetByID retrieves a session by ID
	GetByID(ctx context.Context, id string) (*Session, error)

	// GetByRefreshToken retrieves a session by refresh token hash
	GetByRefreshToken(ctx context.Context, tokenHash string) (*Session, error)

	// UpdateActivity updates the last activity timestamp
	UpdateActivity(ctx context.Context, id string) error

	// Delete deletes a session
	Delete(ctx context.Context, id string) error

	// DeleteByUser deletes all sessions for a user
	DeleteByUser(ctx context.Context, userID string) error

	// List retrieves sessions for a user
	List(ctx context.Context, userID string) ([]*Session, error)

	// DeleteExpired deletes expired sessions
	DeleteExpired(ctx context.Context) (int, error)

	// CountByUser counts active sessions for a user
	CountByUser(ctx context.Context, userID string) (int, error)
}

// AuditRepository defines audit log data access operations
type AuditRepository interface {
	// Create creates a new audit log entry
	Create(ctx context.Context, entry *AuditLog) error

	// List retrieves audit logs with filtering
	List(ctx context.Context, filter *AuditFilter) ([]*AuditLog, error)

	// GetByID retrieves an audit log entry by ID
	GetByID(ctx context.Context, id string) (*AuditLog, error)

	// DeleteOld deletes audit logs older than the specified duration
	DeleteOld(ctx context.Context, olderThan time.Duration) (int, error)
}

// AuditFilter holds filtering options for audit logs
type AuditFilter struct {
	TenantID     string
	UserID       string
	AgentID      string
	Action       string
	ResourceType string
	ResourceID   string
	Success      *bool
	StartTime    time.Time
	EndTime      time.Time
	Limit        int
	Offset       int
}

// PasswordHistoryRepository defines password history data access
type PasswordHistoryRepository interface {
	// Add adds a password hash to history
	Add(ctx context.Context, userID, passwordHash string) error

	// GetRecent retrieves the N most recent password hashes
	GetRecent(ctx context.Context, userID string, count int) ([]string, error)

	// DeleteOld removes password hashes older than N entries
	DeleteOld(ctx context.Context, userID string, keepCount int) error
}
