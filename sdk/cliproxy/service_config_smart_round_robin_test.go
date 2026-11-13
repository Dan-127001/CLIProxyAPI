package cliproxy

import (
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestSmartRoundRobinRoutingSelector(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "Smart"},
	})
	if state.strategy != "smart-round-robin" {
		t.Fatalf("strategy = %q, want smart-round-robin", state.strategy)
	}
	if _, ok := newRoutingSelector(state).(*coreauth.SmartRoundRobinSelector); !ok {
		t.Fatalf("selector type = %T, want *auth.SmartRoundRobinSelector", newRoutingSelector(state))
	}
}
