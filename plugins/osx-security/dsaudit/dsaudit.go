// Package dsaudit provides Directory Services auditing for macOS
//
// This module audits local user accounts via dscl (Directory Service command line)
// and detects:
// - New user accounts
// - Hidden admin accounts (UID < 500)
// - Privilege escalations (users added to admin group)
// - Suspicious account attributes
// - Shadow admin accounts
//
// Build: Part of osx-security plugin for afterdark-darkd
package dsaudit

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// isValidUsername validates that username contains only safe characters
// to prevent command injection. macOS usernames can only contain
// alphanumeric characters, underscore, hyphen, and period.
var validUsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

func isValidUsername(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	return validUsernameRegex.MatchString(name)
}

// User represents a macOS user account
type User struct {
	Name               string            `json:"name"`
	RealName           string            `json:"real_name"`
	UID                int               `json:"uid"`
	GID                int               `json:"gid"`
	HomeDir            string            `json:"home_dir"`
	Shell              string            `json:"shell"`
	IsAdmin            bool              `json:"is_admin"`
	IsHidden           bool              `json:"is_hidden"`
	IsSystemAccount    bool              `json:"is_system_account"`
	CreationTime       time.Time         `json:"creation_time,omitempty"`
	LastLoginTime      time.Time         `json:"last_login_time,omitempty"`
	PasswordLastSet    time.Time         `json:"password_last_set,omitempty"`
	Groups             []string          `json:"groups"`
	AuthenticationHint string            `json:"authentication_hint,omitempty"`
	Picture            string            `json:"picture,omitempty"`
	UniqueID           string            `json:"unique_id"`
	GeneratedUID       string            `json:"generated_uid"`
	Attributes         map[string]string `json:"attributes,omitempty"`
}

// Group represents a macOS group
type Group struct {
	Name     string   `json:"name"`
	GID      int      `json:"gid"`
	Members  []string `json:"members"`
	IsSystem bool     `json:"is_system"`
	UniqueID string   `json:"unique_id"`
}

// Finding represents a security finding from DS audit
type Finding struct {
	Severity    string                 `json:"severity"` // critical, high, medium, low, info
	Type        string                 `json:"type"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	User        string                 `json:"user,omitempty"`
	Group       string                 `json:"group,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
	DetectedAt  time.Time              `json:"detected_at"`
}

// AuditResult contains the results of a Directory Services audit
type AuditResult struct {
	Timestamp      time.Time `json:"timestamp"`
	Users          []User    `json:"users"`
	Groups         []Group   `json:"groups"`
	Findings       []Finding `json:"findings"`
	TotalUsers     int       `json:"total_users"`
	TotalGroups    int       `json:"total_groups"`
	AdminUsers     int       `json:"admin_users"`
	HiddenUsers    int       `json:"hidden_users"`
	SystemAccounts int       `json:"system_accounts"`
	MacOSVersion   string    `json:"macos_version"`
}

// Auditor performs Directory Services auditing
type Auditor struct {
	dsPath      string
	nodePath    string
	lastAudit   *AuditResult
	knownUsers  map[string]User
	knownGroups map[string]Group
}

// NewAuditor creates a new DS auditor
func NewAuditor() *Auditor {
	return &Auditor{
		dsPath:      "/usr/bin/dscl",
		nodePath:    "/var/db/dslocal/nodes/Default",
		knownUsers:  make(map[string]User),
		knownGroups: make(map[string]Group),
	}
}

// Audit performs a complete Directory Services audit
func (a *Auditor) Audit() (*AuditResult, error) {
	result := &AuditResult{
		Timestamp: time.Now(),
		Findings:  make([]Finding, 0),
		Users:     make([]User, 0),
		Groups:    make([]Group, 0),
	}

	// Get macOS version
	if ver, err := a.getMacOSVersion(); err == nil {
		result.MacOSVersion = ver
	}

	// Enumerate users
	users, err := a.enumerateUsers()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate users: %w", err)
	}
	result.Users = users
	result.TotalUsers = len(users)

	// Enumerate groups
	groups, err := a.enumerateGroups()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate groups: %w", err)
	}
	result.Groups = groups
	result.TotalGroups = len(groups)

	// Count statistics
	for _, user := range users {
		if user.IsAdmin {
			result.AdminUsers++
		}
		if user.IsHidden {
			result.HiddenUsers++
		}
		if user.IsSystemAccount {
			result.SystemAccounts++
		}
	}

	// Analyze for security findings
	result.Findings = a.analyze(users, groups)

	// Compare with previous audit if available
	if a.lastAudit != nil {
		changeFindings := a.detectChanges(users, groups)
		result.Findings = append(result.Findings, changeFindings...)
	}

	// Store for next comparison
	a.lastAudit = result
	for _, u := range users {
		a.knownUsers[u.Name] = u
	}
	for _, g := range groups {
		a.knownGroups[g.Name] = g
	}

	return result, nil
}

// enumerateUsers lists all local users
// On darwin, tries native plist parsing first, falls back to dscl
func (a *Auditor) enumerateUsers() ([]User, error) {
	// Try native plist parsing first (defined in dsaudit_darwin.go)
	users, err := a.enumerateUsersNative()
	if err == nil && len(users) > 0 {
		// Enhance users with group membership
		for i := range users {
			users[i].Groups = a.getUserGroupsNative(&users[i])
			users[i].IsAdmin = a.isAdminNative(users[i].Name)
		}
		return users, nil
	}

	// Fallback to dscl (exec.Command)
	return a.enumerateUsersViaCmd()
}

// enumerateUsersViaCmd lists users via dscl command (fallback)
func (a *Auditor) enumerateUsersViaCmd() ([]User, error) {
	// Get list of users
	out, err := exec.Command(a.dsPath, ".", "-list", "/Users").Output()
	if err != nil {
		return nil, fmt.Errorf("dscl list users failed: %w", err)
	}

	var users []User
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		username := strings.TrimSpace(scanner.Text())
		if username == "" {
			continue
		}

		user, err := a.getUserDetails(username)
		if err != nil {
			// Skip users we can't read (permissions)
			continue
		}
		users = append(users, user)
	}

	return users, scanner.Err()
}

// getUserDetails retrieves detailed information about a user
func (a *Auditor) getUserDetails(username string) (User, error) {
	user := User{
		Name:       username,
		Attributes: make(map[string]string),
	}

	// SECURITY: Validate username to prevent command injection
	// Usernames on macOS can only contain alphanumeric, underscore, and hyphen
	if !isValidUsername(username) {
		return user, fmt.Errorf("invalid username format: %s", username)
	}

	// Read all attributes
	out, err := exec.Command(a.dsPath, ".", "-read", "/Users/"+username).Output()
	if err != nil {
		return user, err
	}

	attrs := a.parseAttributes(string(out))
	user.Attributes = attrs

	// Parse specific fields
	if val, ok := attrs["RealName"]; ok {
		user.RealName = val
	}
	if val, ok := attrs["UniqueID"]; ok {
		if uid, err := strconv.Atoi(val); err == nil {
			user.UID = uid
		}
		user.UniqueID = val
	}
	if val, ok := attrs["PrimaryGroupID"]; ok {
		if gid, err := strconv.Atoi(val); err == nil {
			user.GID = gid
		}
	}
	if val, ok := attrs["NFSHomeDirectory"]; ok {
		user.HomeDir = val
	}
	if val, ok := attrs["UserShell"]; ok {
		user.Shell = val
	}
	if val, ok := attrs["GeneratedUID"]; ok {
		user.GeneratedUID = val
	}
	if val, ok := attrs["AuthenticationHint"]; ok {
		user.AuthenticationHint = val
	}
	if val, ok := attrs["Picture"]; ok {
		user.Picture = val
	}

	// Check for hidden flag
	if val, ok := attrs["IsHidden"]; ok && val == "1" {
		user.IsHidden = true
	}

	// Determine if system account (UID < 500 on macOS)
	user.IsSystemAccount = user.UID < 500

	// Hidden if UID < 500 and starts with _
	if strings.HasPrefix(username, "_") {
		user.IsHidden = true
		user.IsSystemAccount = true
	}

	// Get group memberships
	user.Groups = a.getUserGroups(username)

	// Check if admin
	user.IsAdmin = a.isUserAdmin(username)

	return user, nil
}

// parseAttributes parses dscl output into key-value pairs
func (a *Auditor) parseAttributes(output string) map[string]string {
	attrs := make(map[string]string)
	var currentKey string
	var currentValue strings.Builder

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, " ") {
			// Continuation of previous value
			if currentKey != "" {
				if currentValue.Len() > 0 {
					currentValue.WriteString("\n")
				}
				currentValue.WriteString(strings.TrimSpace(line))
			}
		} else if strings.Contains(line, ":") {
			// Save previous key-value
			if currentKey != "" {
				attrs[currentKey] = currentValue.String()
			}
			// Start new key
			parts := strings.SplitN(line, ":", 2)
			currentKey = strings.TrimSpace(parts[0])
			currentValue.Reset()
			if len(parts) > 1 {
				currentValue.WriteString(strings.TrimSpace(parts[1]))
			}
		}
	}
	// Save last key-value
	if currentKey != "" {
		attrs[currentKey] = currentValue.String()
	}

	return attrs
}

// getUserGroups returns all groups a user belongs to
func (a *Auditor) getUserGroups(username string) []string {
	out, err := exec.Command("id", "-Gn", username).Output()
	if err != nil {
		return nil
	}
	groups := strings.Fields(strings.TrimSpace(string(out)))
	return groups
}

// isUserAdmin checks if user is in admin group
func (a *Auditor) isUserAdmin(username string) bool {
	groups := a.getUserGroups(username)
	for _, g := range groups {
		if g == "admin" || g == "wheel" {
			return true
		}
	}
	return false
}

// enumerateGroups lists all local groups
func (a *Auditor) enumerateGroups() ([]Group, error) {
	out, err := exec.Command(a.dsPath, ".", "-list", "/Groups").Output()
	if err != nil {
		return nil, fmt.Errorf("dscl list groups failed: %w", err)
	}

	var groups []Group
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		groupname := strings.TrimSpace(scanner.Text())
		if groupname == "" {
			continue
		}

		group, err := a.getGroupDetails(groupname)
		if err != nil {
			continue
		}
		groups = append(groups, group)
	}

	return groups, scanner.Err()
}

// getGroupDetails retrieves detailed information about a group
func (a *Auditor) getGroupDetails(groupname string) (Group, error) {
	group := Group{
		Name: groupname,
	}

	// SECURITY: Validate groupname to prevent command injection
	if !isValidUsername(groupname) {
		return group, fmt.Errorf("invalid group name format: %s", groupname)
	}

	out, err := exec.Command(a.dsPath, ".", "-read", "/Groups/"+groupname).Output()
	if err != nil {
		return group, err
	}

	attrs := a.parseAttributes(string(out))

	if val, ok := attrs["PrimaryGroupID"]; ok {
		if gid, err := strconv.Atoi(val); err == nil {
			group.GID = gid
		}
	}
	if val, ok := attrs["GeneratedUID"]; ok {
		group.UniqueID = val
	}
	if val, ok := attrs["GroupMembership"]; ok {
		group.Members = strings.Fields(val)
	}

	// System groups typically have GID < 500 or start with _
	group.IsSystem = group.GID < 500 || strings.HasPrefix(groupname, "_")

	return group, nil
}

// analyze performs security analysis on users and groups
func (a *Auditor) analyze(users []User, groups []Group) []Finding {
	var findings []Finding

	for _, user := range users {
		// Check for hidden admin accounts (red flag)
		if user.IsAdmin && user.IsHidden && !user.IsSystemAccount {
			findings = append(findings, Finding{
				Severity:    "critical",
				Type:        "hidden_admin",
				Title:       "Hidden Admin Account Detected",
				Description: fmt.Sprintf("User '%s' is hidden but has admin privileges. This could indicate a backdoor account.", user.Name),
				User:        user.Name,
				Details: map[string]interface{}{
					"uid":      user.UID,
					"home_dir": user.HomeDir,
					"shell":    user.Shell,
				},
				DetectedAt: time.Now(),
			})
		}

		// Check for non-standard admin UIDs
		if user.IsAdmin && user.UID < 500 && !user.IsSystemAccount && user.Name != "root" {
			findings = append(findings, Finding{
				Severity:    "high",
				Type:        "suspicious_uid",
				Title:       "Admin Account with Low UID",
				Description: fmt.Sprintf("User '%s' is admin with UID %d (typically reserved for system accounts).", user.Name, user.UID),
				User:        user.Name,
				Details: map[string]interface{}{
					"uid": user.UID,
				},
				DetectedAt: time.Now(),
			})
		}

		// Check for users with /bin/bash or /bin/zsh that look suspicious
		if (user.Shell == "/bin/bash" || user.Shell == "/bin/zsh") && user.IsHidden {
			findings = append(findings, Finding{
				Severity:    "medium",
				Type:        "hidden_interactive",
				Title:       "Hidden Account with Interactive Shell",
				Description: fmt.Sprintf("Hidden user '%s' has an interactive shell (%s).", user.Name, user.Shell),
				User:        user.Name,
				Details: map[string]interface{}{
					"shell": user.Shell,
				},
				DetectedAt: time.Now(),
			})
		}

		// Check for empty or suspicious home directories
		if user.HomeDir == "" || user.HomeDir == "/" {
			if !user.IsSystemAccount && user.UID >= 500 {
				findings = append(findings, Finding{
					Severity:    "medium",
					Type:        "suspicious_homedir",
					Title:       "Suspicious Home Directory",
					Description: fmt.Sprintf("User '%s' has empty or root home directory.", user.Name),
					User:        user.Name,
					Details: map[string]interface{}{
						"home_dir": user.HomeDir,
					},
					DetectedAt: time.Now(),
				})
			}
		}

		// Check for accounts with no password set (dangerous if interactive shell)
		// This would need enhanced authorization to check properly
	}

	// Check admin group membership
	for _, group := range groups {
		if group.Name == "admin" || group.Name == "wheel" {
			for _, member := range group.Members {
				// Check if member is a real user account
				found := false
				for _, u := range users {
					if u.Name == member {
						found = true
						break
					}
				}
				if !found {
					findings = append(findings, Finding{
						Severity:    "high",
						Type:        "phantom_admin",
						Title:       "Phantom Admin Group Member",
						Description: fmt.Sprintf("User '%s' is in %s group but not in local users database.", member, group.Name),
						User:        member,
						Group:       group.Name,
						DetectedAt:  time.Now(),
					})
				}
			}
		}
	}

	return findings
}

// detectChanges compares current state with previous audit
func (a *Auditor) detectChanges(currentUsers []User, currentGroups []Group) []Finding {
	var findings []Finding

	// Build current state maps
	currentUserMap := make(map[string]User)
	for _, u := range currentUsers {
		currentUserMap[u.Name] = u
	}

	currentGroupMap := make(map[string]Group)
	for _, g := range currentGroups {
		currentGroupMap[g.Name] = g
	}

	// Detect new users
	for name, user := range currentUserMap {
		if _, existed := a.knownUsers[name]; !existed {
			severity := "medium"
			if user.IsAdmin {
				severity = "high"
			}
			findings = append(findings, Finding{
				Severity:    severity,
				Type:        "new_user",
				Title:       "New User Account Created",
				Description: fmt.Sprintf("New user '%s' was created (UID: %d, Admin: %v).", name, user.UID, user.IsAdmin),
				User:        name,
				Details: map[string]interface{}{
					"uid":      user.UID,
					"admin":    user.IsAdmin,
					"home_dir": user.HomeDir,
					"shell":    user.Shell,
				},
				DetectedAt: time.Now(),
			})
		}
	}

	// Detect deleted users
	for name := range a.knownUsers {
		if _, exists := currentUserMap[name]; !exists {
			findings = append(findings, Finding{
				Severity:    "medium",
				Type:        "deleted_user",
				Title:       "User Account Deleted",
				Description: fmt.Sprintf("User '%s' was deleted.", name),
				User:        name,
				DetectedAt:  time.Now(),
			})
		}
	}

	// Detect privilege escalation
	for name, currentUser := range currentUserMap {
		if prevUser, existed := a.knownUsers[name]; existed {
			if currentUser.IsAdmin && !prevUser.IsAdmin {
				findings = append(findings, Finding{
					Severity:    "critical",
					Type:        "privilege_escalation",
					Title:       "User Granted Admin Privileges",
					Description: fmt.Sprintf("User '%s' was granted admin privileges.", name),
					User:        name,
					Details: map[string]interface{}{
						"previous_groups": prevUser.Groups,
						"current_groups":  currentUser.Groups,
					},
					DetectedAt: time.Now(),
				})
			}
		}
	}

	// Detect admin group changes
	for name, currentGroup := range currentGroupMap {
		if name == "admin" || name == "wheel" {
			if prevGroup, existed := a.knownGroups[name]; existed {
				// Check for new members
				prevMembers := make(map[string]bool)
				for _, m := range prevGroup.Members {
					prevMembers[m] = true
				}
				for _, member := range currentGroup.Members {
					if !prevMembers[member] {
						findings = append(findings, Finding{
							Severity:    "high",
							Type:        "admin_group_addition",
							Title:       "User Added to Admin Group",
							Description: fmt.Sprintf("User '%s' was added to '%s' group.", member, name),
							User:        member,
							Group:       name,
							DetectedAt:  time.Now(),
						})
					}
				}
			}
		}
	}

	return findings
}

// getMacOSVersion returns the macOS version string
func (a *Auditor) getMacOSVersion() (string, error) {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// GetUser returns details for a specific user
func (a *Auditor) GetUser(username string) (*User, error) {
	user, err := a.getUserDetails(username)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// GetGroup returns details for a specific group
func (a *Auditor) GetGroup(groupname string) (*Group, error) {
	group, err := a.getGroupDetails(groupname)
	if err != nil {
		return nil, err
	}
	return &group, nil
}

// GetAdminUsers returns all admin users
func (a *Auditor) GetAdminUsers() ([]User, error) {
	users, err := a.enumerateUsers()
	if err != nil {
		return nil, err
	}

	var admins []User
	for _, u := range users {
		if u.IsAdmin {
			admins = append(admins, u)
		}
	}
	return admins, nil
}

// GetHiddenUsers returns all hidden users
func (a *Auditor) GetHiddenUsers() ([]User, error) {
	users, err := a.enumerateUsers()
	if err != nil {
		return nil, err
	}

	var hidden []User
	for _, u := range users {
		if u.IsHidden && !u.IsSystemAccount {
			hidden = append(hidden, u)
		}
	}
	return hidden, nil
}
