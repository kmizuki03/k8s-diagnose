package rbac

import (
	"strings"
	"testing"
)

func TestGeneratedReaderIncludesRuleAndSpecialPermissions(t *testing.T) {
	documents, err := Documents("prod")
	if err != nil {
		t.Fatal(err)
	}
	cluster := string(documents["k8s-diagnose-clusterrole.yaml"])
	for _, value := range []string{"endpointslices", "leases", "apiservices", "customresourcedefinitions", "pods/log", "/readyz"} {
		if !strings.Contains(cluster, value) {
			t.Fatalf("ClusterRoleに %s がない", value)
		}
	}
	role := string(documents["k8s-diagnose-role.yaml"])
	if !strings.Contains(role, "namespace: prod") || strings.Contains(role, "/readyz") {
		t.Fatalf("Roleのscopeが不正: %s", role)
	}
}

func TestDocumentsRejectsInvalidNamespace(t *testing.T) {
	for _, namespace := range []string{"", "UPPER", "bad namespace", "bad\nnamespace"} {
		if _, err := Documents(namespace); err == nil {
			t.Fatalf("不正なnamespaceを受理した: %q", namespace)
		}
	}
}
