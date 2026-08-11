package rules

import "testing"

func TestSelectModeIncludesDetailedPodDiagnosticInputs(t *testing.T) {
	registry := Builtins()
	keys := registry.RequiredKeys("select")
	for _, key := range []string{
		"pods", "all_pods", "nodes", "pod_metrics",
		"configmaps", "secrets", "serviceaccounts", "priorityclasses", "runtimeclasses",
		"pvcs", "pvs", "storageclasses", "events", "limitranges",
		"services", "endpoints", "endpoint_slices", "networkpolicies",
		"ingresses", "ingressclasses",
	} {
		if !keys[key] {
			t.Errorf("selectモードの診断入力に%qが含まれていない", key)
		}
	}
	wantedRules := map[string]bool{
		"config-risks": false, "pod-metrics": false, "persistent-volumes": false,
		"network-policies": false, "limit-ranges": false, "ingress": false, "tls": false,
	}
	for _, rule := range registry.Rules() {
		metadata := rule.Metadata()
		if _, wanted := wantedRules[metadata.ID]; !wanted {
			continue
		}
		for _, mode := range metadata.Modes {
			if mode == "select" {
				wantedRules[metadata.ID] = true
			}
		}
	}
	for id, enabled := range wantedRules {
		if !enabled {
			t.Errorf("ルール%qがselectモードで有効になっていない", id)
		}
	}
}
