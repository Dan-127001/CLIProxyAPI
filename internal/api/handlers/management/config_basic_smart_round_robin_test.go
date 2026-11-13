package management

import "testing"

func TestNormalizeRoutingStrategySmartRoundRobin(t *testing.T) {
	for _, input := range []string{"smart-round-robin", "SmartRoundRobin", "smart", "srr"} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "smart-round-robin" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v; want smart-round-robin, true", input, got, ok)
		}
	}
}
