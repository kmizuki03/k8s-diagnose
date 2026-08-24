package rules

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// GatewayAPIRule validates the cross-resource references and hostname
// attachment rules that the Gateway API controller otherwise exposes only in
// status conditions.
type GatewayAPIRule struct{}

func (GatewayAPIRule) Metadata() Metadata {
	permissions := cluster("gateway.networking.k8s.io", "gatewayclasses")
	permissions = append(permissions, namespaced("gateway.networking.k8s.io", "gateways,httproutes")...)
	permissions = append(permissions, namespaced("", "services")...)
	permissions = append(permissions, namespaced("", "pods")...)
	return Metadata{
		ID: "gateway-api", Section: "Gateway API", Description: "GatewayClass・Gateway・HTTPRouteの参照と接続条件",
		Required: []string{"gateways", "httproutes"}, Optional: []string{"gatewayclasses", "services", "pods"},
		Permissions: permissions, Modes: []string{"all", "triage"},
	}
}

func (GatewayAPIRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	classes := map[string]struct{}{}
	gateways := map[string]*unstructured.Unstructured{}
	services := map[string]struct{}{}
	classDataAvailable := snapshot.AvailableOrUntracked("gatewayclasses")
	for i := range snapshot.GatewayClasses {
		classes[snapshot.GatewayClasses[i].GetName()] = struct{}{}
	}
	for i := range snapshot.Gateways {
		gateway := &snapshot.Gateways[i]
		gateways[gateway.GetNamespace()+"/"+gateway.GetName()] = gateway
		className, _, _ := unstructured.NestedString(gateway.Object, "spec", "gatewayClassName")
		if _, ok := classes[className]; classDataAvailable && className != "" && !ok {
			result = append(result, model.NewFinding(model.Issue, "K8S.GATEWAY.CLASS_NOT_FOUND", "Gateway API", ref("Gateway", gateway.GetNamespace(), gateway.GetName()), "GatewayClassNotFound", className,
				fmt.Sprintf("Gateway %s が参照する GatewayClass %q は存在しません", shortRef(gateway.GetNamespace(), gateway.GetName()), className), 100))
		}
		result = append(result, gatewayConditionFindings(gateway)...)
	}
	for i := range snapshot.Services {
		services[snapshot.Services[i].Namespace+"/"+snapshot.Services[i].Name] = struct{}{}
	}
	for i := range snapshot.HTTPRoutes {
		route := &snapshot.HTTPRoutes[i]
		result = append(result, routeConditionFindings(route)...)
		parents, _, _ := unstructured.NestedSlice(route.Object, "spec", "parentRefs")
		for _, raw := range parents {
			parent, ok := raw.(map[string]any)
			if !ok || stringField(parent, "group", "gateway.networking.k8s.io") != "gateway.networking.k8s.io" || stringField(parent, "kind", "Gateway") != "Gateway" {
				continue
			}
			namespace := stringField(parent, "namespace", route.GetNamespace())
			name := stringField(parent, "name", "")
			gateway := gateways[namespace+"/"+name]
			if gateway == nil {
				if snapshot.ScopeNamespace != "" && namespace != snapshot.ScopeNamespace {
					continue
				}
				result = append(result, model.NewFinding(model.Issue, "K8S.HTTPROUTE.PARENT_NOT_FOUND", "Gateway API", ref("HTTPRoute", route.GetNamespace(), route.GetName()), "ParentGatewayNotFound", namespace+"/"+name,
					fmt.Sprintf("HTTPRoute %s が parentRef で参照する Gateway %s/%s は存在しません", shortRef(route.GetNamespace(), route.GetName()), namespace, name), 100))
				continue
			}
			if !routeHostnameMatchesGateway(route, gateway, stringField(parent, "sectionName", "")) {
				result = append(result, model.NewFinding(model.Warning, "K8S.HTTPROUTE.HOSTNAME_MISMATCH", "Gateway API", ref("HTTPRoute", route.GetNamespace(), route.GetName()), "NoMatchingListenerHostname", namespace+"/"+name,
					fmt.Sprintf("HTTPRoute %s の hostnames は、親Gateway %s のlistener hostnameと一致しません。このRouteはlistenerへ接続できません", shortRef(route.GetNamespace(), route.GetName()), shortRef(namespace, name)), 95))
			}
		}
		if snapshot.AvailableOrUntracked("services") {
			result = append(result, missingRouteBackends(route, services, snapshot.ScopeNamespace)...)
			if snapshot.AvailableOrUntracked("pods") {
				result = append(result, routeBackendPathFindings(route, snapshot)...)
			}
		}
	}
	return result
}

var applicationHTTPPath = regexp.MustCompile(`(?m)(?:self\.path\s*==|URL\.Path\s*==)\s*["'](/[^"']*)["']`)

type routePathMatch struct {
	Type  string
	Value string
}

func routeBackendPathFindings(route *unstructured.Unstructured, snapshot *kube.Snapshot) []model.Finding {
	result := []model.Finding{}
	rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	for ruleIndex, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		if routeRuleRewritesPath(rule) {
			// The backend sees the rewritten path, not spec.matches[].path.
			// Without evaluating the filter, comparing the original path would
			// produce a false mismatch.
			continue
		}
		paths := []routePathMatch{}
		matches, _ := rule["matches"].([]any)
		for _, rawMatch := range matches {
			match, ok := rawMatch.(map[string]any)
			if !ok {
				continue
			}
			path, _ := match["path"].(map[string]any)
			if path == nil {
				continue
			}
			if value := stringField(path, "value", ""); value != "" {
				pathType := stringField(path, "type", "PathPrefix")
				if pathType == "RegularExpression" {
					paths = nil
					break
				}
				paths = append(paths, routePathMatch{Type: pathType, Value: value})
			}
		}
		if paths == nil {
			continue
		}
		if len(paths) == 0 {
			paths = append(paths, routePathMatch{Type: "PathPrefix", Value: "/"})
		}
		backends, _ := rule["backendRefs"].([]any)
		for _, rawBackend := range backends {
			backend, ok := rawBackend.(map[string]any)
			if !ok || stringField(backend, "group", "") != "" || stringField(backend, "kind", "Service") != "Service" {
				continue
			}
			name := stringField(backend, "name", "")
			namespace := stringField(backend, "namespace", route.GetNamespace())
			if snapshot.ScopeNamespace != "" && namespace != snapshot.ScopeNamespace {
				continue
			}
			var selector map[string]string
			for i := range snapshot.Services {
				service := &snapshot.Services[i]
				if service.Namespace == namespace && service.Name == name {
					selector = service.Spec.Selector
					break
				}
			}
			if len(selector) == 0 {
				continue
			}
			appPaths := map[string]struct{}{}
			for i := range snapshot.Pods {
				pod := &snapshot.Pods[i]
				if pod.Namespace != namespace || !labelsContain(pod.Labels, selector) {
					continue
				}
				for _, container := range pod.Spec.Containers {
					text := strings.Join(append(append([]string{}, container.Command...), container.Args...), " ")
					for _, match := range applicationHTTPPath.FindAllStringSubmatch(text, -1) {
						if len(match) > 1 {
							appPaths[match[1]] = struct{}{}
						}
					}
				}
			}
			if len(appPaths) == 0 {
				continue
			}
			compatible := false
			for appPath := range appPaths {
				for _, routePath := range paths {
					if routePathAccepts(routePath, appPath) {
						compatible = true
					}
				}
			}
			if compatible {
				continue
			}
			result = append(result, model.NewFinding(model.Candidate, "K8S.HTTPROUTE.PATH_BACKEND_MISMATCH", "Gateway API", ref("HTTPRoute", route.GetNamespace(), route.GetName()), "PathDoesNotMatchBackend", fmt.Sprintf("rule/%d/backend/%s", ruleIndex, name),
				fmt.Sprintf("HTTPRoute %s のrule[%d]が受け付けるpath %s は、backend Service %s/%s のPod command/argsから確認できたHTTP path %s と一致しません。check.shと同じpathを送るとbackendが404を返す可能性があります", shortRef(route.GetNamespace(), route.GetName()), ruleIndex, routePathText(paths), namespace, name, stringSetText(appPaths)), 82))
		}
	}
	return result
}

func routeRuleRewritesPath(rule map[string]any) bool {
	filters, _ := rule["filters"].([]any)
	for _, raw := range filters {
		filter, ok := raw.(map[string]any)
		if ok && stringField(filter, "type", "") == "URLRewrite" {
			return true
		}
	}
	return false
}

func routePathAccepts(match routePathMatch, path string) bool {
	if match.Type == "Exact" {
		return path == match.Value
	}
	prefix := strings.TrimSuffix(match.Value, "/")
	if prefix == "" {
		return strings.HasPrefix(path, "/")
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func routePathText(paths []routePathMatch) string {
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		values = append(values, path.Type+" "+path.Value)
	}
	return strings.Join(values, ", ")
}

func labelsContain(labels, selector map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func stringSetText(values map[string]struct{}) string {
	items := make([]string, 0, len(values))
	for value := range values {
		items = append(items, value)
	}
	sort.Strings(items)
	return strings.Join(items, ", ")
}

func stringField(value map[string]any, key, fallback string) string {
	if text, ok := value[key].(string); ok && text != "" {
		return text
	}
	return fallback
}

func gatewayConditionFindings(gateway *unstructured.Unstructured) []model.Finding {
	return objectFalseConditionFindings(gateway, "Gateway", []string{"Accepted", "Programmed"}, "K8S.GATEWAY.CONDITION")
}

func routeConditionFindings(route *unstructured.Unstructured) []model.Finding {
	wanted := map[string]struct{}{"Accepted": {}, "ResolvedRefs": {}}
	parents, _, _ := unstructured.NestedSlice(route.Object, "status", "parents")
	result := []model.Finding{}
	for parentIndex, rawParent := range parents {
		parent, ok := rawParent.(map[string]any)
		if !ok {
			continue
		}
		conditions, _ := parent["conditions"].([]any)
		for _, rawCondition := range conditions {
			condition, ok := rawCondition.(map[string]any)
			if !ok || stringField(condition, "status", "") != "False" {
				continue
			}
			typeName := stringField(condition, "type", "")
			if _, ok := wanted[typeName]; !ok {
				continue
			}
			reason := stringField(condition, "reason", "ConditionFalse")
			result = append(result, model.NewFinding(model.Warning, "K8S.HTTPROUTE.CONDITION", "Gateway API", ref("HTTPRoute", route.GetNamespace(), route.GetName()), reason, fmt.Sprintf("parent/%d/%s", parentIndex, typeName),
				conditionStateMessage("HTTPRoute", shortRef(route.GetNamespace(), route.GetName()), typeName, "False", reason), 90,
				model.Evidence{Kind: "condition", Key: typeName, Value: stringField(condition, "message", "")}))
		}
	}
	return result
}

func objectFalseConditionFindings(item *unstructured.Unstructured, kind string, types []string, code string) []model.Finding {
	wanted := map[string]struct{}{}
	for _, value := range types {
		wanted[value] = struct{}{}
	}
	conditions, _, _ := unstructured.NestedSlice(item.Object, "status", "conditions")
	result := []model.Finding{}
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if !ok || stringField(condition, "status", "") != "False" {
			continue
		}
		typeName := stringField(condition, "type", "")
		if _, ok := wanted[typeName]; !ok {
			continue
		}
		reason := stringField(condition, "reason", "ConditionFalse")
		result = append(result, model.NewFinding(model.Warning, code, "Gateway API", ref(kind, item.GetNamespace(), item.GetName()), reason, typeName,
			conditionStateMessage(kind, shortRef(item.GetNamespace(), item.GetName()), typeName, "False", reason), 90,
			model.Evidence{Kind: "condition", Key: typeName, Value: stringField(condition, "message", "")}))
	}
	return result
}

func routeHostnameMatchesGateway(route, gateway *unstructured.Unstructured, sectionName string) bool {
	routeHosts, _, _ := unstructured.NestedStringSlice(route.Object, "spec", "hostnames")
	listeners, _, _ := unstructured.NestedSlice(gateway.Object, "spec", "listeners")
	if len(routeHosts) == 0 {
		return true
	}
	for _, raw := range listeners {
		listener, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if sectionName != "" && stringField(listener, "name", "") != sectionName {
			continue
		}
		listenerHost := stringField(listener, "hostname", "")
		if listenerHost == "" {
			return true
		}
		for _, routeHost := range routeHosts {
			if hostnameIntersects(listenerHost, routeHost) {
				return true
			}
		}
	}
	return false
}

func hostnameIntersects(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSuffix(a, ".")), strings.ToLower(strings.TrimSuffix(b, "."))
	if a == b {
		return true
	}
	if strings.HasPrefix(a, "*.") && strings.HasPrefix(b, "*.") {
		// Gateway API wildcards replace exactly one DNS label. Different
		// wildcard suffixes therefore cannot describe a common hostname.
		return false
	}
	if strings.HasPrefix(a, "*.") {
		return wildcardHostnameMatches(a, b)
	}
	if strings.HasPrefix(b, "*.") {
		return wildcardHostnameMatches(b, a)
	}
	return false
}

func wildcardHostnameMatches(pattern, hostname string) bool {
	suffix := strings.TrimPrefix(pattern, "*.")
	remainder := strings.TrimSuffix(hostname, "."+suffix)
	return remainder != hostname && remainder != "" && !strings.Contains(remainder, ".")
}

func missingRouteBackends(route *unstructured.Unstructured, services map[string]struct{}, scopeNamespace string) []model.Finding {
	result := []model.Finding{}
	rules, _, _ := unstructured.NestedSlice(route.Object, "spec", "rules")
	for _, rawRule := range rules {
		rule, ok := rawRule.(map[string]any)
		if !ok {
			continue
		}
		backends, _ := rule["backendRefs"].([]any)
		for _, rawBackend := range backends {
			backend, ok := rawBackend.(map[string]any)
			if !ok || stringField(backend, "group", "") != "" || stringField(backend, "kind", "Service") != "Service" {
				continue
			}
			name := stringField(backend, "name", "")
			namespace := stringField(backend, "namespace", route.GetNamespace())
			if _, ok := services[namespace+"/"+name]; ok {
				continue
			}
			if scopeNamespace != "" && namespace != scopeNamespace {
				continue
			}
			result = append(result, model.NewFinding(model.Issue, "K8S.HTTPROUTE.BACKEND_NOT_FOUND", "Gateway API", ref("HTTPRoute", route.GetNamespace(), route.GetName()), "BackendServiceNotFound", name,
				fmt.Sprintf("HTTPRoute %s が backendRef で参照する Service %s/%s は存在しません", shortRef(route.GetNamespace(), route.GetName()), namespace, name), 100))
		}
	}
	return result
}
