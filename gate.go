package main

import (
	"github.com/raelx/gate-ip-whitelist/plugins/ipwhitelist"
	"go.minekube.com/gate/cmd/gate"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// It's a normal Go program, we only need
// to register our plugins and execute Gate.
func main() {
	// Here we register our plugins with the proxy.
	proxy.Plugins = append(proxy.Plugins,
		// IP whitelist plugin for access control
		ipwhitelist.Plugin,

		// Add more plugins as you like.
		// They will be initialized in the same order as appended.
	)

	// Simply execute Gate as if it was a normal Go program.
	// Gate will take care of everything else for us,
	// such as config auto-reloading and flags like --debug.
	gate.Execute()
}
