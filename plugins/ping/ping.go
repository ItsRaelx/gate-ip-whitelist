package ping

import (
	"context"
	"fmt"
	"github.com/go-logr/logr"
	. "github.com/raelx/gate-ip-whitelist/util"
	"github.com/raelx/gate-ip-whitelist/util/mini"
	"github.com/robinbraemer/event"
	"go.minekube.com/common/minecraft/color"
	c "go.minekube.com/common/minecraft/component"
	"go.minekube.com/gate/pkg/edition/java/proto/version"
	"go.minekube.com/gate/pkg/edition/java/proxy"
)

// Plugin is a ping plugin that handles ping events.
var Plugin = proxy.Plugin{
	Name: "Ping",
	Init: func(ctx context.Context, p *proxy.Proxy) error {
		log := logr.FromContextOrDiscard(ctx)
		log.Info("Hello from Ping plugin!")

		event.Subscribe(p.Event(), 0, onPing())

		return nil
	},
}

func onPing() func(*proxy.PingEvent) {
	line2 := mini.Gradient(
		"Join, test and extend your Gate proxy!",
		c.Style{Bold: c.True},
		*color.Yellow.RGB, *color.Gold.RGB, *color.Red.RGB,
	)

	return func(e *proxy.PingEvent) {
		// Check if connection and ping are valid
		if e.Connection() == nil {
			return
		}
		
		ping := e.Ping()
		if ping == nil {
			return
		}
		
		clientVersion := version.Protocol(e.Connection().Protocol())
		line1 := mini.Gradient(
			fmt.Sprintf("Hey %s user!\n", clientVersion),
			c.Style{},
			*color.White.RGB, *color.LightPurple.RGB,
		)

		ping.Description = Join(line1, line2)
		
		// Check if Players field is not nil before accessing
		if ping.Players != nil {
			ping.Players.Max = ping.Players.Online + 1
		}
	}
}
