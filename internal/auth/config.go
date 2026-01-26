package auth

import "time"

// Config holds all authentication/authorization configuration
type Config struct {
	// JWT settings
	JWT JWTSettings `yaml:"jwt" json:"jwt"`

	// API key settings
	APIKey APIKeySettings `yaml:"api_key" json:"api_key"`

	// Agent token settings
	Agent AgentSettings `yaml:"agent" json:"agent"`

	// Session settings
	Session SessionSettings `yaml:"session" json:"session"`

	// Password policy
	Password PasswordSettings `yaml:"password" json:"password"`

	// Rate limiting
	RateLimit RateLimitSettings `yaml:"rate_limit" json:"rate_limit"`

	// Security settings
	Security SecuritySettings `yaml:"security" json:"security"`
}

// JWTSettings holds JWT configuration
type JWTSettings struct {
	Secret        string        `yaml:"secret" json:"-"`
	AccessExpiry  time.Duration `yaml:"access_expiry" json:"access_expiry"`
	RefreshExpiry time.Duration `yaml:"refresh_expiry" json:"refresh_expiry"`
	Issuer        string        `yaml:"issuer" json:"issuer"`
	Audience      []string      `yaml:"audience" json:"audience"`
}

// APIKeySettings holds API key configuration
type APIKeySettings struct {
	Prefix      string        `yaml:"prefix" json:"prefix"`
	MaxAge      time.Duration `yaml:"max_age" json:"max_age"`
	MaxPerUser  int           `yaml:"max_per_user" json:"max_per_user"`
	AllowExpiry bool          `yaml:"allow_expiry" json:"allow_expiry"`
}

// AgentSettings holds agent token configuration
type AgentSettings struct {
	TokenExpiry     time.Duration `yaml:"token_expiry" json:"token_expiry"`
	AllowRotation   bool          `yaml:"allow_rotation" json:"allow_rotation"`
	RotationWindow  time.Duration `yaml:"rotation_window" json:"rotation_window"`
	RequireApproval bool          `yaml:"require_approval" json:"require_approval"`
}

// SessionSettings holds session configuration
type SessionSettings struct {
	Timeout            time.Duration `yaml:"timeout" json:"timeout"`
	MaxPerUser         int           `yaml:"max_per_user" json:"max_per_user"`
	ExtendOnActivity   bool          `yaml:"extend_on_activity" json:"extend_on_activity"`
	InvalidateOnLogout bool          `yaml:"invalidate_on_logout" json:"invalidate_on_logout"`
}

// PasswordSettings holds password policy configuration
type PasswordSettings struct {
	MinLength       int  `yaml:"min_length" json:"min_length"`
	RequireUpper    bool `yaml:"require_upper" json:"require_upper"`
	RequireLower    bool `yaml:"require_lower" json:"require_lower"`
	RequireDigit    bool `yaml:"require_digit" json:"require_digit"`
	RequireSpecial  bool `yaml:"require_special" json:"require_special"`
	MaxAge          int  `yaml:"max_age_days" json:"max_age_days"` // 0 = no expiry
	PreventReuse    int  `yaml:"prevent_reuse" json:"prevent_reuse"` // Number of previous passwords to check
}

// RateLimitSettings holds rate limiting configuration
type RateLimitSettings struct {
	LoginAttempts    int           `yaml:"login_attempts" json:"login_attempts"`
	LoginWindow      time.Duration `yaml:"login_window" json:"login_window"`
	LockoutDuration  time.Duration `yaml:"lockout_duration" json:"lockout_duration"`
	APIRequestsLimit int           `yaml:"api_requests_limit" json:"api_requests_limit"`
	APIRequestWindow time.Duration `yaml:"api_request_window" json:"api_request_window"`
}

// SecuritySettings holds security configuration
type SecuritySettings struct {
	AllowedOrigins    []string `yaml:"allowed_origins" json:"allowed_origins"`
	TrustedProxies    []string `yaml:"trusted_proxies" json:"trusted_proxies"`
	RequireHTTPS      bool     `yaml:"require_https" json:"require_https"`
	SecureCookies     bool     `yaml:"secure_cookies" json:"secure_cookies"`
	CSRFProtection    bool     `yaml:"csrf_protection" json:"csrf_protection"`
	IPWhitelist       []string `yaml:"ip_whitelist" json:"ip_whitelist"`
	MFARequired       bool     `yaml:"mfa_required" json:"mfa_required"`
	AuditAllRequests  bool     `yaml:"audit_all_requests" json:"audit_all_requests"`
}

// DefaultConfig returns configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		JWT: JWTSettings{
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 7 * 24 * time.Hour,
			Issuer:        "afterdark",
			Audience:      []string{"afterdark-api"},
		},
		APIKey: APIKeySettings{
			Prefix:      "ads_",
			MaxAge:      365 * 24 * time.Hour,
			MaxPerUser:  10,
			AllowExpiry: true,
		},
		Agent: AgentSettings{
			TokenExpiry:     30 * 24 * time.Hour,
			AllowRotation:   true,
			RotationWindow:  24 * time.Hour,
			RequireApproval: false,
		},
		Session: SessionSettings{
			Timeout:            30 * time.Minute,
			MaxPerUser:         5,
			ExtendOnActivity:   true,
			InvalidateOnLogout: true,
		},
		Password: PasswordSettings{
			MinLength:      12,
			RequireUpper:   true,
			RequireLower:   true,
			RequireDigit:   true,
			RequireSpecial: true,
			MaxAge:         0, // No expiry by default
			PreventReuse:   5,
		},
		RateLimit: RateLimitSettings{
			LoginAttempts:    5,
			LoginWindow:      15 * time.Minute,
			LockoutDuration:  30 * time.Minute,
			APIRequestsLimit: 1000,
			APIRequestWindow: time.Minute,
		},
		Security: SecuritySettings{
			AllowedOrigins:   []string{},
			TrustedProxies:   []string{"127.0.0.1", "::1"},
			RequireHTTPS:     true,
			SecureCookies:    true,
			CSRFProtection:   true,
			IPWhitelist:      []string{},
			MFARequired:      false,
			AuditAllRequests: true,
		},
	}
}

// ToJWTConfig converts auth config to JWTConfig
func (c *Config) ToJWTConfig() *JWTConfig {
	return &JWTConfig{
		Secret:          []byte(c.JWT.Secret),
		AccessExpiry:    c.JWT.AccessExpiry,
		RefreshExpiry:   c.JWT.RefreshExpiry,
		AgentExpiry:     c.Agent.TokenExpiry,
		Issuer:          c.JWT.Issuer,
		AllowedAudience: c.JWT.Audience,
	}
}

// ToPasswordConfig converts auth config to PasswordConfig
func (c *Config) ToPasswordConfig() *PasswordConfig {
	return &PasswordConfig{
		MinLength:      c.Password.MinLength,
		RequireUpper:   c.Password.RequireUpper,
		RequireLower:   c.Password.RequireLower,
		RequireDigit:   c.Password.RequireDigit,
		RequireSpecial: c.Password.RequireSpecial,
	}
}
