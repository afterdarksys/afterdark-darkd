module github.com/afterdarksys/afterdark-darkd/plugins/osx-security

go 1.25.2

require (
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/auth v0.0.0
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/dsaudit v0.0.0
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/fsmonitor v0.0.0
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/keywatch v0.0.0
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/snapshot v0.0.0
)

require (
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
)

// Use local packages
replace (
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/auth => ./auth
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/dsaudit => ./dsaudit
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/fsmonitor => ./fsmonitor
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/keywatch => ./keywatch
	github.com/afterdarksys/afterdark-darkd/plugins/osx-security/snapshot => ./snapshot
)
