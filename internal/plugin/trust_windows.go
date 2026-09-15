//go:build windows

package plugin

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func validatePluginOwner(path string, _ os.FileInfo) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	trusted := func(s *windows.SID) bool {
		return s != nil && (s.IsWellKnown(windows.WinLocalSystemSid) || s.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return fmt.Errorf("plugin owner must be SYSTEM or Administrators")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return fmt.Errorf("plugin requires an explicit DACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported plugin ACL entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		const writeMask = 0x10000000 | 0x40000000 | 0x00010000 | 0x00040000 | 0x00080000 | 0x2 | 0x4 | 0x10 | 0x100
		if uint32(ace.Mask)&writeMask != 0 && !trusted(sid) {
			return fmt.Errorf("untrusted principal can modify plugin")
		}
	}
	return nil
}
