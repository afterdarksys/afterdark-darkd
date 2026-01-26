package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Service errors
var (
	ErrInvalidCredentials  = errors.New("invalid email or password")
	ErrAccountLocked       = errors.New("account is locked")
	ErrAccountInactive     = errors.New("account is inactive")
	ErrTenantSuspended     = errors.New("tenant is suspended")
	ErrAgentLimitReached   = errors.New("agent limit reached for tenant")
	ErrSessionLimitReached = errors.New("maximum sessions reached")
	ErrMFARequired         = errors.New("MFA verification required")
	ErrPasswordExpired     = errors.New("password has expired")
	ErrPasswordReused      = errors.New("password was recently used")
)

// AuthService provides authentication and authorization operations
type AuthService struct {
	config     *Config
	jwtService *JWTService
	pwdService *PasswordService
	evaluator  *PermissionEvaluator

	// Repositories
	tenants         TenantRepository
	users           UserRepository
	roles           RoleRepository
	sites           SiteRepository
	apiKeys         APIKeyRepository
	agentTokens     AgentTokenRepository
	sessions        SessionRepository
	audit           AuditRepository
	passwordHistory PasswordHistoryRepository
}

// AuthServiceConfig holds dependencies for AuthService
type AuthServiceConfig struct {
	Config              *Config
	TenantRepo          TenantRepository
	UserRepo            UserRepository
	RoleRepo            RoleRepository
	SiteRepo            SiteRepository
	APIKeyRepo          APIKeyRepository
	AgentTokenRepo      AgentTokenRepository
	SessionRepo         SessionRepository
	AuditRepo           AuditRepository
	PasswordHistoryRepo PasswordHistoryRepository
}

// NewAuthService creates a new auth service
func NewAuthService(cfg *AuthServiceConfig) *AuthService {
	jwtConfig := cfg.Config.ToJWTConfig()
	pwdConfig := cfg.Config.ToPasswordConfig()

	return &AuthService{
		config:          cfg.Config,
		jwtService:      NewJWTService(jwtConfig),
		pwdService:      NewPasswordService(pwdConfig),
		evaluator:       NewPermissionEvaluator(),
		tenants:         cfg.TenantRepo,
		users:           cfg.UserRepo,
		roles:           cfg.RoleRepo,
		sites:           cfg.SiteRepo,
		apiKeys:         cfg.APIKeyRepo,
		agentTokens:     cfg.AgentTokenRepo,
		sessions:        cfg.SessionRepo,
		audit:           cfg.AuditRepo,
		passwordHistory: cfg.PasswordHistoryRepo,
	}
}

// LoginResult contains the result of a successful login
type LoginResult struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         *User     `json:"user"`
	Tenant       *Tenant   `json:"tenant"`
	MFARequired  bool      `json:"mfa_required,omitempty"`
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(ctx context.Context, email, password, ipAddress, userAgent string) (*LoginResult, error) {
	// Find user by email (check all tenants or require tenant context)
	user, err := s.findUserByEmail(ctx, email)
	if err != nil {
		s.logAuthFailure(ctx, "", email, "login", "user not found", ipAddress)
		return nil, ErrInvalidCredentials
	}

	// Check tenant status
	tenant, err := s.tenants.GetByID(ctx, user.TenantID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if tenant.Status != StatusActive {
		s.logAuthFailure(ctx, user.TenantID, email, "login", "tenant suspended", ipAddress)
		return nil, ErrTenantSuspended
	}

	// Check user status
	if user.Status == StatusLocked {
		if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
			s.logAuthFailure(ctx, user.TenantID, email, "login", "account locked", ipAddress)
			return nil, ErrAccountLocked
		}
		// Lock expired, unlock the account
		s.users.UnlockUser(ctx, user.ID)
	}
	if user.Status == StatusInactive || user.Status == StatusDeleted {
		s.logAuthFailure(ctx, user.TenantID, email, "login", "account inactive", ipAddress)
		return nil, ErrAccountInactive
	}

	// Verify password
	if err := s.pwdService.VerifyPassword(password, user.PasswordHash); err != nil {
		s.users.IncrementFailedLogins(ctx, user.ID)

		// Check if should lock
		if user.FailedLogins+1 >= s.config.RateLimit.LoginAttempts {
			lockUntil := time.Now().Add(s.config.RateLimit.LockoutDuration)
			s.users.LockUser(ctx, user.ID, lockUntil)
		}

		s.logAuthFailure(ctx, user.TenantID, email, "login", "invalid password", ipAddress)
		return nil, ErrInvalidCredentials
	}

	// Reset failed logins on successful auth
	s.users.ResetFailedLogins(ctx, user.ID)

	// Check if MFA is required
	if user.MFAEnabled || s.config.Security.MFARequired {
		return &LoginResult{
			User:        user,
			Tenant:      tenant,
			MFARequired: true,
		}, nil
	}

	// Generate tokens
	return s.generateLoginTokens(ctx, user, tenant, ipAddress, userAgent)
}

// generateLoginTokens creates access and refresh tokens for a user
func (s *AuthService) generateLoginTokens(ctx context.Context, user *User, tenant *Tenant, ipAddress, userAgent string) (*LoginResult, error) {
	// Get user roles and permissions
	roles, err := s.roles.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}

	var roleValues []Role
	for _, r := range roles {
		if r != nil {
			roleValues = append(roleValues, *r)
		}
	}
	permissions := GetEffectivePermissions(roleValues)

	// Get user's site assignments
	siteIDs, err := s.getUserSiteIDs(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sites: %w", err)
	}

	// Generate tokens
	accessToken, err := s.jwtService.GenerateAccessToken(user, roleNames, permissions, siteIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtService.GenerateRefreshToken(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Check session limit
	sessionCount, _ := s.sessions.CountByUser(ctx, user.ID)
	if sessionCount >= s.config.Session.MaxPerUser {
		// Delete oldest session
		sessions, _ := s.sessions.List(ctx, user.ID)
		if len(sessions) > 0 {
			s.sessions.Delete(ctx, sessions[0].ID)
		}
	}

	// Create session
	session := &Session{
		UserID:       user.ID,
		TenantID:     user.TenantID,
		RefreshToken: hashToken(refreshToken),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		ExpiresAt:    time.Now().Add(s.config.JWT.RefreshExpiry),
		LastActivity: time.Now(),
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	s.users.UpdateLastLogin(ctx, user.ID)

	// Log successful login
	s.logAuthSuccess(ctx, user.TenantID, user.ID, "login", ipAddress)

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(s.config.JWT.AccessExpiry),
		User:         user,
		Tenant:       tenant,
	}, nil
}

// RefreshToken generates a new access token from a refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*LoginResult, error) {
	// Validate refresh token
	claims, err := s.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != TokenTypeRefresh {
		return nil, ErrInvalidToken
	}

	// Find session
	session, err := s.sessions.GetByRefreshToken(ctx, hashToken(refreshToken))
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Get user
	user, err := s.users.GetByID(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	// Get tenant
	tenant, err := s.tenants.GetByID(ctx, user.TenantID)
	if err != nil {
		return nil, err
	}

	// Verify user and tenant are still active
	if user.Status != StatusActive {
		return nil, ErrAccountInactive
	}
	if tenant.Status != StatusActive {
		return nil, ErrTenantSuspended
	}

	// Get updated roles and permissions
	roles, _ := s.roles.GetUserRoles(ctx, user.ID)
	roleNames := make([]string, len(roles))
	for i, r := range roles {
		roleNames[i] = r.Name
	}
	var roleValues []Role
	for _, r := range roles {
		if r != nil {
			roleValues = append(roleValues, *r)
		}
	}
	permissions := GetEffectivePermissions(roleValues)
	siteIDs, _ := s.getUserSiteIDs(ctx, user.ID)

	// Generate new access token
	accessToken, err := s.jwtService.GenerateAccessToken(user, roleNames, permissions, siteIDs)
	if err != nil {
		return nil, err
	}

	// Update session activity
	s.sessions.UpdateActivity(ctx, session.ID)

	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // Return same refresh token
		ExpiresAt:    time.Now().Add(s.config.JWT.AccessExpiry),
		User:         user,
		Tenant:       tenant,
	}, nil
}

// Logout invalidates a user's session
func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	session, err := s.sessions.GetByRefreshToken(ctx, hashToken(refreshToken))
	if err != nil {
		return nil // Session already invalid
	}

	return s.sessions.Delete(ctx, session.ID)
}

// LogoutAll invalidates all sessions for a user
func (s *AuthService) LogoutAll(ctx context.Context, userID string) error {
	return s.sessions.DeleteByUser(ctx, userID)
}

// RegisterAgent creates a token for a new endpoint agent
func (s *AuthService) RegisterAgent(ctx context.Context, tenantID, siteID, agentID string) (string, error) {
	// Check tenant exists and is active
	tenant, err := s.tenants.GetByID(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if tenant.Status != StatusActive {
		return "", ErrTenantSuspended
	}

	// Check agent limit
	agentCount, _ := s.tenants.CountAgents(ctx, tenantID)
	if agentCount >= tenant.MaxAgents {
		return "", ErrAgentLimitReached
	}

	// Generate agent token
	token, err := s.jwtService.GenerateAgentToken(tenantID, siteID, agentID)
	if err != nil {
		return "", err
	}

	// Store token
	agentToken := &AgentToken{
		TenantID:  tenantID,
		SiteID:    siteID,
		AgentID:   agentID,
		TokenHash: hashToken(token),
		ExpiresAt: time.Now().Add(s.config.Agent.TokenExpiry),
	}
	if err := s.agentTokens.Create(ctx, agentToken); err != nil {
		return "", err
	}

	s.logAuthSuccess(ctx, tenantID, agentID, "agent_register", "")

	return token, nil
}

// CreateAPIKey creates a new API key for a user
func (s *AuthService) CreateAPIKey(ctx context.Context, tenantID, userID, name string, permissions []string, expiresAt *time.Time) (*APIKey, string, error) {
	// Check user's API key count
	existingKeys, _ := s.apiKeys.ListByUser(ctx, userID)
	if len(existingKeys) >= s.config.APIKey.MaxPerUser {
		return nil, "", errors.New("maximum API keys reached")
	}

	// Generate key
	keyString, prefix, err := GenerateAPIKey()
	if err != nil {
		return nil, "", err
	}

	// Create API key record
	apiKey := &APIKey{
		TenantID:    tenantID,
		Name:        name,
		KeyHash:     hashToken(keyString),
		Prefix:      prefix,
		Permissions: permissions,
		ExpiresAt:   expiresAt,
		CreatedBy:   userID,
	}

	if err := s.apiKeys.Create(ctx, apiKey); err != nil {
		return nil, "", err
	}

	return apiKey, keyString, nil
}

// ChangePassword changes a user's password
func (s *AuthService) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify current password
	if err := s.pwdService.VerifyPassword(currentPassword, user.PasswordHash); err != nil {
		return ErrInvalidCredentials
	}

	// Validate new password
	if err := s.pwdService.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Check password history
	if s.config.Password.PreventReuse > 0 {
		history, _ := s.passwordHistory.GetRecent(ctx, userID, s.config.Password.PreventReuse)
		for _, oldHash := range history {
			if s.pwdService.VerifyPassword(newPassword, oldHash) == nil {
				return ErrPasswordReused
			}
		}
	}

	// Hash new password
	newHash, err := s.pwdService.HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update user
	user.PasswordHash = newHash
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}

	// Add to password history
	s.passwordHistory.Add(ctx, userID, newHash)

	// Invalidate all sessions
	s.sessions.DeleteByUser(ctx, userID)

	return nil
}

// Helper methods

func (s *AuthService) findUserByEmail(ctx context.Context, email string) (*User, error) {
	// For multi-tenant, we might need to search across tenants or require tenant context
	// For now, assume we have tenant context or search all
	return nil, ErrNotFound // Placeholder - implement based on requirements
}

func (s *AuthService) getUserSiteIDs(ctx context.Context, userID string) ([]string, error) {
	// Get site IDs from user role assignments
	// Return empty slice if user has tenant-wide access
	return []string{}, nil
}

func (s *AuthService) logAuthSuccess(ctx context.Context, tenantID, subjectID, action, ipAddress string) {
	if s.audit == nil {
		return
	}

	entry := &AuditLog{
		TenantID:  tenantID,
		UserID:    &subjectID,
		Action:    action,
		IPAddress: ipAddress,
		Success:   true,
		CreatedAt: time.Now(),
	}
	s.audit.Create(ctx, entry)
}

func (s *AuthService) logAuthFailure(ctx context.Context, tenantID, identifier, action, reason, ipAddress string) {
	if s.audit == nil {
		return
	}

	entry := &AuditLog{
		TenantID:     tenantID,
		Action:       action,
		IPAddress:    ipAddress,
		Success:      false,
		ErrorMessage: reason,
		CreatedAt:    time.Now(),
		Details: map[string]interface{}{
			"identifier": identifier,
		},
	}
	s.audit.Create(ctx, entry)
}

// hashToken creates a hash of a token for storage
func hashToken(token string) string {
	// Use a simple hash for token storage
	// In production, consider using SHA-256
	return token // Placeholder - implement proper hashing
}
