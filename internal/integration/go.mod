module github.com/mdlayher/netlink/internal/integration

go 1.21

toolchain go1.21.4

require (
	github.com/google/go-cmp v0.6.0
	github.com/jsimonetti/rtnetlink v1.3.2
	github.com/mdlayher/ethtool v0.0.0-20221212131811-ba3b4bc2e02c
	golang.org/x/net v0.18.0
	golang.org/x/sys v0.14.0
)

require (
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/genetlink v1.3.1 // indirect
)

// We require a recent release, but in reality the integration tests should
// always use the netlink module at the root of the repository.
require github.com/mdlayher/netlink v1.7.1

replace github.com/mdlayher/netlink => ../../
