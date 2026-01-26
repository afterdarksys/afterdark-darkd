//go:build darwin

package dsaudit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"howett.net/plist"
)

// UserPlist represents the structure of /var/db/dslocal/nodes/Default/users/*.plist
type UserPlist struct {
	Name               []string `plist:"name"`
	RealName           []string `plist:"realname"`
	UID                []string `plist:"uid"`
	PrimaryGroupID     []string `plist:"gid"`
	Home               []string `plist:"home"`
	Shell              []string `plist:"shell"`
	GeneratedUID       []string `plist:"generateduid"`
	AuthenticationHint []string `plist:"hint"`
	IsHidden           []string `plist:"IsHidden"`
	Picture            []string `plist:"picture"`
}

// GroupPlist represents the structure of /var/db/dslocal/nodes/Default/groups/*.plist
type GroupPlist struct {
	Name            []string `plist:"name"`
	GID             []string `plist:"gid"`
	GroupMembership []string `plist:"GroupMembership"`
	GeneratedUID    []string `plist:"generateduid"`
}

// enumerateUsersNative lists all local users by parsing plist files directly
// instead of exec.Command("dscl", ".", "-list", "/Users")
func (a *Auditor) enumerateUsersNative() ([]User, error) {
	usersDir := filepath.Join(a.nodePath, "users")
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, err
	}

	var users []User
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}

		plistPath := filepath.Join(usersDir, entry.Name())
		user, err := a.parseUserPlist(plistPath)
		if err != nil {
			continue // Skip unreadable plist files
		}

		users = append(users, user)
	}

	return users, nil
}

// parseUserPlist parses a single user plist file
func (a *Auditor) parseUserPlist(path string) (User, error) {
	var user User

	file, err := os.Open(path)
	if err != nil {
		return user, err
	}
	defer file.Close()

	var plistData UserPlist
	decoder := plist.NewDecoder(file)
	if err := decoder.Decode(&plistData); err != nil {
		return user, err
	}

	// Extract first value from each array (plist stores as arrays)
	if len(plistData.Name) > 0 {
		user.Name = plistData.Name[0]
	}
	if len(plistData.RealName) > 0 {
		user.RealName = plistData.RealName[0]
	}
	if len(plistData.UID) > 0 {
		user.UID, _ = strconv.Atoi(plistData.UID[0])
	}
	if len(plistData.PrimaryGroupID) > 0 {
		user.GID, _ = strconv.Atoi(plistData.PrimaryGroupID[0])
	}
	if len(plistData.Home) > 0 {
		user.HomeDir = plistData.Home[0]
	}
	if len(plistData.Shell) > 0 {
		user.Shell = plistData.Shell[0]
	}
	if len(plistData.GeneratedUID) > 0 {
		user.GeneratedUID = plistData.GeneratedUID[0]
	}
	if len(plistData.AuthenticationHint) > 0 {
		user.AuthenticationHint = plistData.AuthenticationHint[0]
	}
	if len(plistData.Picture) > 0 {
		user.Picture = plistData.Picture[0]
	}
	if len(plistData.IsHidden) > 0 && plistData.IsHidden[0] == "1" {
		user.IsHidden = true
	}

	// Determine if system account (UID < 500)
	user.IsSystemAccount = user.UID < 500

	// UniqueID is filename without .plist
	user.UniqueID = strings.TrimSuffix(filepath.Base(path), ".plist")

	return user, nil
}

// enumerateGroupsNative lists all local groups by parsing plist files directly
// instead of exec.Command("dscl", ".", "-list", "/Groups")
func (a *Auditor) enumerateGroupsNative() ([]Group, error) {
	groupsDir := filepath.Join(a.nodePath, "groups")
	entries, err := os.ReadDir(groupsDir)
	if err != nil {
		return nil, err
	}

	var groups []Group
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}

		plistPath := filepath.Join(groupsDir, entry.Name())
		group, err := a.parseGroupPlist(plistPath)
		if err != nil {
			continue
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// parseGroupPlist parses a single group plist file
func (a *Auditor) parseGroupPlist(path string) (Group, error) {
	var group Group

	file, err := os.Open(path)
	if err != nil {
		return group, err
	}
	defer file.Close()

	var plistData GroupPlist
	decoder := plist.NewDecoder(file)
	if err := decoder.Decode(&plistData); err != nil {
		return group, err
	}

	if len(plistData.Name) > 0 {
		group.Name = plistData.Name[0]
	}
	if len(plistData.GID) > 0 {
		group.GID, _ = strconv.Atoi(plistData.GID[0])
	}
	if len(plistData.GeneratedUID) > 0 {
		group.UniqueID = plistData.GeneratedUID[0]
	}
	group.Members = plistData.GroupMembership

	// System group if GID < 500
	group.IsSystem = group.GID < 500

	return group, nil
}

// checkUserInGroupNative checks if a user is in a group by reading group plist
func (a *Auditor) checkUserInGroupNative(username, groupName string) (bool, error) {
	groupPath := filepath.Join(a.nodePath, "groups", groupName+".plist")
	group, err := a.parseGroupPlist(groupPath)
	if err != nil {
		return false, err
	}

	for _, member := range group.Members {
		if member == username {
			return true, nil
		}
	}
	return false, nil
}

// isAdminNative checks if a user is in the admin group using native plist parsing
func (a *Auditor) isAdminNative(username string) bool {
	inAdmin, _ := a.checkUserInGroupNative(username, "admin")
	return inAdmin
}

// getUserGroupsNative returns all groups a user belongs to using native plist parsing
func (a *Auditor) getUserGroupsNative(user *User) []string {
	groupsDir := filepath.Join(a.nodePath, "groups")
	entries, err := os.ReadDir(groupsDir)
	if err != nil {
		return nil
	}

	var groups []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
			continue
		}

		plistPath := filepath.Join(groupsDir, entry.Name())
		group, err := a.parseGroupPlist(plistPath)
		if err != nil {
			continue
		}

		for _, member := range group.Members {
			if member == user.Name {
				groups = append(groups, group.Name)
				break
			}
		}
	}

	return groups
}
