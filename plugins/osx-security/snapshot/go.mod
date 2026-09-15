module github.com/afterdarksys/afterdark-darkd/plugins/osx-security/snapshot

go 1.25.2

require (
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/dsaudit v0.0.0
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/keywatch v0.0.0
)

require howett.net/plist v1.0.1 // indirect

replace (
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/dsaudit => ../dsaudit
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/keywatch => ../keywatch
)
