package auth

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// Context keys for auth data
type contextKey string

const (
	ClaimsContextKey   contextKey = "auth_claims"
	TenantContextKey   contextKey = "auth_tenant"
	SubjectContextKey  contextKey = "auth_subject"
	APIKeyContextKey   contextKey = "auth_apikey"
)

// Subject represents the authenticated entity (user, agent, or API key)
type Subject struct {
	ID          string
	Type        string // "user", "agent", "apikey"
	TenantID    string
	Email       string
	Roles       []string
	Permissions []string
	SiteIDs     []string
}

// Middleware provides authentication and authorization middleware
type Middleware struct {
	jwtService  *JWTService
	evaluator   *PermissionEvaluator
	apiKeyStore APIKeyStore
	auditLogger AuditLogger
}

// APIKeyStore interface for validating API keys
type APIKeyStore interface {
	ValidateAPIKey(ctx context.Context, key string) (*APIKey, error)
	UpdateLastUsed(ctx context.Context, keyID string) error
}

// AuditLogger interface for logging auth events
type AuditLogger interface {
	LogAuthEvent(ctx context.Context, event *AuditLog) error
}

// MiddlewareConfig holds middleware configuration
type MiddlewareConfig struct {
	JWTService  *JWTService
	APIKeyStore APIKeyStore
	AuditLogger AuditLogger
}

// NewMiddleware creates a new auth middleware
func NewMiddleware(config *MiddlewareConfig) *Middleware {
	return &Middleware{
		jwtService:  config.JWTService,
		evaluator:   NewPermissionEvaluator(),
		apiKeyStore: config.APIKeyStore,
		auditLogger: config.AuditLogger,
	}
}

// Authenticate extracts and validates credentials from the request
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var subject *Subject
		var err error

		// Try Bearer token first
		if token := extractBearerToken(r); token != "" {
			subject, err = m.authenticateJWT(r.Context(), token)
		} else if apiKey := extractAPIKey(r); apiKey != "" {
			// Try API key
			subject, err = m.authenticateAPIKey(r.Context(), apiKey)
		}

		if err != nil {
			m.logAuthFailure(r, err)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if subject == nil {
			http.Error(w, "Unauthorized: no credentials provided", http.StatusUnauthorized)
			return
		}

		// Add subject to context
		ctx := context.WithValue(r.Context(), SubjectContextKey, subject)
		ctx = context.WithValue(ctx, TenantContextKey, subject.TenantID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticateJWT validates a JWT token and returns the subject
func (m *Middleware) authenticateJWT(ctx context.Context, token string) (*Subject, error) {
	claims, err := m.jwtService.ValidateToken(token)
	if err != nil {
		return nil, err
	}

	subjectType := "user"
	if claims.TokenType == TokenTypeAgent {
		subjectType = "agent"
	}

	return &Subject{
		ID:          claims.UserID,
		Type:        subjectType,
		TenantID:    claims.TenantID,
		Email:       claims.Email,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		SiteIDs:     claims.SiteIDs,
	}, nil
}

// authenticateAPIKey validates an API key and returns the subject
func (m *Middleware) authenticateAPIKey(ctx context.Context, key string) (*Subject, error) {
	if m.apiKeyStore == nil {
		return nil, ErrInvalidToken
	}

	apiKey, err := m.apiKeyStore.ValidateAPIKey(ctx, key)
	if err != nil {
		return nil, err
	}

	// Update last used timestamp asynchronously
	go m.apiKeyStore.UpdateLastUsed(context.Background(), apiKey.ID)

	return &Subject{
		ID:          apiKey.ID,
		Type:        "apikey",
		TenantID:    apiKey.TenantID,
		Permissions: apiKey.Permissions,
		SiteIDs:     apiKey.SiteIDs,
	}, nil
}

// RequireAuth ensures the request is authenticated (alias for Authenticate)
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return m.Authenticate(next)
}

// RequirePermission checks if the subject has the required permission
func (m *Middleware) RequirePermission(resource, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := SubjectFromContext(r.Context())
			if subject == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			if !m.evaluator.HasPermission(subject.Permissions, resource, action) {
				m.logAuthzFailure(r, resource, action)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole checks if the subject has one of the required roles
func (m *Middleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := SubjectFromContext(r.Context())
			if subject == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			hasRole := false
			for _, required := range roles {
				for _, userRole := range subject.Roles {
					if userRole == required {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenant checks if the subject belongs to the specified tenant
func (m *Middleware) RequireTenant(tenantIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := SubjectFromContext(r.Context())
			if subject == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get tenant ID from URL parameter or use subject's tenant
			requestedTenant := r.URL.Query().Get(tenantIDParam)
			if requestedTenant == "" {
				requestedTenant = r.PathValue(tenantIDParam)
			}

			// Superadmins (global scope) can access any tenant
			if m.evaluator.HasPermissionWithScope(subject.Permissions, "*", "*", ScopeGlobal) {
				next.ServeHTTP(w, r)
				return
			}

			// Others can only access their own tenant
			if requestedTenant != "" && requestedTenant != subject.TenantID {
				http.Error(w, "Forbidden: cannot access other tenant", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireSiteAccess checks if the subject has access to the specified site
func (m *Middleware) RequireSiteAccess(siteIDParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := SubjectFromContext(r.Context())
			if subject == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Get site ID from URL parameter
			requestedSite := r.URL.Query().Get(siteIDParam)
			if requestedSite == "" {
				requestedSite = r.PathValue(siteIDParam)
			}

			// If no site specified or user has tenant-wide access
			if requestedSite == "" || len(subject.SiteIDs) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Check if user has access to the site
			hasAccess := false
			for _, siteID := range subject.SiteIDs {
				if siteID == requestedSite {
					hasAccess = true
					break
				}
			}

			if !hasAccess {
				http.Error(w, "Forbidden: no access to this site", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AuditLog wraps a handler to log all requests
func (m *Middleware) AuditLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		// Log the request
		if m.auditLogger != nil {
			subject := SubjectFromContext(r.Context())
			var userID, tenantID *string
			if subject != nil {
				userID = &subject.ID
				tenantID = &subject.TenantID
			}

			log := &AuditLog{
				TenantID:     stringOrEmpty(tenantID),
				UserID:       userID,
				Action:       r.Method + " " + r.URL.Path,
				IPAddress:    getClientIP(r),
				UserAgent:    r.UserAgent(),
				Success:      wrapped.statusCode < 400,
				CreatedAt:    time.Now(),
				Details: map[string]interface{}{
					"duration_ms": time.Since(start).Milliseconds(),
					"status_code": wrapped.statusCode,
				},
			}

			go m.auditLogger.LogAuthEvent(context.Background(), log)
		}
	})
}

// Helper functions

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	return parts[1]
}

func extractAPIKey(r *http.Request) string {
	// Check header first
	if key := r.Header.Get("X-API-Key"); key != "" {
		return key
	}

	// Check query parameter as fallback (less secure, for testing)
	return r.URL.Query().Get("api_key")
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}

	return r.RemoteAddr
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (m *Middleware) logAuthFailure(r *http.Request, err error) {
	if m.auditLogger == nil {
		return
	}

	log := &AuditLog{
		Action:       "auth_failure",
		IPAddress:    getClientIP(r),
		UserAgent:    r.UserAgent(),
		Success:      false,
		ErrorMessage: err.Error(),
		CreatedAt:    time.Now(),
		Details: map[string]interface{}{
			"path":   r.URL.Path,
			"method": r.Method,
		},
	}

	go m.auditLogger.LogAuthEvent(context.Background(), log)
}

func (m *Middleware) logAuthzFailure(r *http.Request, resource, action string) {
	if m.auditLogger == nil {
		return
	}

	subject := SubjectFromContext(r.Context())
	var userID, tenantID *string
	if subject != nil {
		userID = &subject.ID
		tenantID = &subject.TenantID
	}

	log := &AuditLog{
		TenantID:     stringOrEmpty(tenantID),
		UserID:       userID,
		Action:       "authz_failure",
		ResourceType: resource,
		IPAddress:    getClientIP(r),
		UserAgent:    r.UserAgent(),
		Success:      false,
		ErrorMessage: "insufficient permissions",
		CreatedAt:    time.Now(),
		Details: map[string]interface{}{
			"requested_resource": resource,
			"requested_action":   action,
			"path":               r.URL.Path,
			"method":             r.Method,
		},
	}

	go m.auditLogger.LogAuthEvent(context.Background(), log)
}

// SubjectFromContext extracts the Subject from request context
func SubjectFromContext(ctx context.Context) *Subject {
	subject, _ := ctx.Value(SubjectContextKey).(*Subject)
	return subject
}

// TenantIDFromContext extracts the tenant ID from request context
func TenantIDFromContext(ctx context.Context) string {
	tenantID, _ := ctx.Value(TenantContextKey).(string)
	return tenantID
}

// ClaimsFromContext extracts JWT claims from request context
func ClaimsFromContext(ctx context.Context) *JWTClaims {
	claims, _ := ctx.Value(ClaimsContextKey).(*JWTClaims)
	return claims
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
