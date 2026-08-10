// Package rules contains Kubernetes diagnostic analyzers and root-cause correlation.
package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
)

type Permission struct {
	APIGroups []string
	Resources []string
	Verbs     []string
	Scope     string
}

type Metadata struct {
	ID                  string
	Section             string
	Description         string
	Required            []string
	UnavailableCode     string
	UnavailableResource string
	// Optional inputs enrich a rule but never suppress its core evaluation.
	// Their acquisition is still counted in Coverage and reported explicitly.
	Optional    []string
	Permissions []Permission
	Modes       []string
}

type Rule interface {
	Metadata() Metadata
	Evaluate(context.Context, *kube.Snapshot, config.Config) []model.Finding
}

type Registry struct{ rules []Rule }

func NewRegistry(values ...Rule) *Registry {
	seen := map[string]struct{}{}
	for _, rule := range values {
		id := rule.Metadata().ID
		if id == "" {
			panic("rule ID must not be empty")
		}
		if _, ok := seen[id]; ok {
			panic("duplicate rule ID: " + id)
		}
		seen[id] = struct{}{}
	}
	return &Registry{rules: append([]Rule{}, values...)}
}

func (r *Registry) Rules() []Rule { return append([]Rule{}, r.rules...) }

// RequiredKeys returns the exact collector inputs needed by enabled rules.
// This keeps --list cheap and avoids requesting resources unrelated to a mode.
func (r *Registry) RequiredKeys(mode string) map[string]bool {
	result := map[string]bool{}
	for _, rule := range r.rules {
		meta := rule.Metadata()
		if len(meta.Modes) > 0 && !contains(meta.Modes, mode) {
			continue
		}
		for _, key := range meta.Required {
			result[key] = true
		}
		for _, key := range meta.Optional {
			result[key] = true
		}
	}
	return result
}

func (r *Registry) Run(ctx context.Context, snapshot *kube.Snapshot, cfg config.Config, state *model.State) {
	recordPodObservations(snapshot, state)
	for _, rule := range r.rules {
		meta := rule.Metadata()
		if len(meta.Modes) > 0 && !contains(meta.Modes, cfg.Mode) {
			continue
		}
		missing := []string{}
		reasons := []string{}
		for _, key := range meta.Required {
			status := snapshot.Status(key)
			if !status.Available {
				missing = append(missing, key)
				if status.Reason != "" {
					reasons = append(reasons, key+"="+status.Reason)
				}
			}
		}
		if len(missing) > 0 {
			reason := strings.Join(reasons, "; ")
			state.AddCheck(model.Check{ID: meta.ID, Section: meta.Section, Description: meta.Description, Available: false, Reason: reason})
			code, resource, message := "K8S.API.RULE_UNAVAILABLE", "Rule/"+meta.ID,
				fmt.Sprintf("%sを実施できません (取得不能: %s)", meta.Description, strings.Join(missing, ", "))
			if meta.UnavailableCode != "" && len(missing) == 1 {
				code, resource = meta.UnavailableCode, meta.UnavailableResource
				message = fmt.Sprintf("%sを取得できません (%s)", meta.Description, fetchStatusLabel(snapshot.Status(missing[0])))
			}
			finding := model.NewFinding(model.Unavailable, code, meta.Section, resource, "FetchUnavailable", meta.ID,
				message, 100,
				model.Evidence{Kind: "api", Key: "reason", Value: reason})
			finding.RuleID = meta.ID
			state.Add(finding)
			continue
		}
		// Optional-only rules (currently readyz/livez) are fully represented by
		// their individual acquisition checks. Adding an unconditional parent
		// success would inflate Coverage even when every endpoint is unavailable.
		if len(meta.Required) > 0 || len(meta.Optional) == 0 {
			state.AddCheck(model.Check{ID: meta.ID, Section: meta.Section, Description: meta.Description, Available: true})
		}
		for _, key := range meta.Optional {
			status := snapshot.Status(key)
			checkID := meta.ID + "/optional/" + key
			if status.Available {
				state.AddCheck(model.Check{ID: checkID, Section: meta.Section, Description: meta.Description + " (任意取得: " + key + ")", Available: true})
				continue
			}
			state.AddCheck(model.Check{ID: checkID, Section: meta.Section, Description: meta.Description + " (任意取得: " + key + ")", Available: false, Reason: status.Reason})
			finding := model.NewFinding(model.Unavailable, "K8S.API.PARTIAL_UNAVAILABLE", meta.Section, "Rule/"+meta.ID, "OptionalFetchUnavailable", "optional/"+key,
				fmt.Sprintf("%sの一部を評価できません (取得不能: %s)", meta.Description, key), 100,
				model.Evidence{Kind: "api", Key: key, Value: status.Reason})
			finding.RuleID = meta.ID
			state.Add(finding)
		}
		for _, finding := range rule.Evaluate(ctx, snapshot, cfg) {
			if finding.RuleID == "" {
				finding.RuleID = meta.ID
			}
			state.Add(finding)
		}
	}
	state.Sort()
}

func recordPodObservations(snapshot *kube.Snapshot, state *model.State) {
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		podResource := ref("Pod", pod.Namespace, pod.Name)
		uid := string(pod.UID)
		if uid == "" {
			uid = "unknown"
		}
		record := func(containerType, name string, restartCount int32) {
			id := strings.Join([]string{podResource, containerType, name, uid}, "|")
			state.Observe("pod_restarts", id, map[string]any{
				"resource": podResource, "container": name, "container_type": containerType,
				"pod_uid": uid, "restart_count": restartCount,
			})
		}
		for _, status := range pod.Status.InitContainerStatuses {
			record("init", status.Name, status.RestartCount)
		}
		for _, status := range pod.Status.ContainerStatuses {
			record("app", status.Name, status.RestartCount)
		}
		for _, status := range pod.Status.EphemeralContainerStatuses {
			record("ephemeral", status.Name, status.RestartCount)
		}
	}
}

func (r *Registry) Permissions() []Permission {
	type key struct{ group, resource, scope string }
	grouped := map[key]map[string]struct{}{}
	for _, rule := range r.rules {
		for _, permission := range rule.Metadata().Permissions {
			for _, group := range permission.APIGroups {
				for _, resource := range permission.Resources {
					k := key{group, resource, permission.Scope}
					if grouped[k] == nil {
						grouped[k] = map[string]struct{}{}
					}
					for _, verb := range permission.Verbs {
						grouped[k][verb] = struct{}{}
					}
				}
			}
		}
	}
	result := []Permission{}
	keys := make([]key, 0, len(grouped))
	for k := range grouped {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return fmt.Sprintf("%s/%s/%s", keys[i].group, keys[i].resource, keys[i].scope) < fmt.Sprintf("%s/%s/%s", keys[j].group, keys[j].resource, keys[j].scope)
	})
	for _, k := range keys {
		verbs := []string{}
		for v := range grouped[k] {
			verbs = append(verbs, v)
		}
		sort.Strings(verbs)
		result = append(result, Permission{APIGroups: []string{k.group}, Resources: []string{k.resource}, Verbs: verbs, Scope: k.scope})
	}
	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func Builtins() *Registry {
	return NewRegistry(
		PodHealthRule{}, WorkloadRule{}, NodeRule{}, NodeHeartbeatRule{}, NodeMetricsRule{}, PodMetricsRule{}, JobRule{}, CronJobRule{}, HPARule{},
		SchedulingRule{},
		DependencyRule{}, PriorityClassDependencyRule{}, RuntimeClassDependencyRule{},
		ServiceRule{}, IngressRule{}, StorageRule{}, PersistentVolumeRule{}, NetworkPolicyRule{},
		WebhookRule{}, TLSRule{}, QuotaRule{}, PDBRule{}, APIServiceRule{},
		ConfigRiskRule{}, ProbeConfigRule{}, LimitRangeRule{}, NamespaceRule{}, CRDRule{}, ControlPlaneRule{}, APIDeprecationRule{},
	)
}

func fetchStatusLabel(status kube.FetchStatus) string {
	switch status.Status {
	case kube.StatusNotFound:
		return "API未提供 (NotFound)"
	case kube.StatusUnavailable:
		return "API到達不能"
	case kube.StatusForbidden:
		return "RBAC Forbidden"
	case kube.StatusUnauthorized:
		return "Unauthorized"
	case kube.StatusTimeout:
		return "タイムアウト"
	case kube.StatusInvalid:
		return "API要求不正"
	default:
		if status.Reason != "" {
			return status.Reason
		}
		return "APIエラー"
	}
}

func namespaced(groups, resources string) []Permission {
	return []Permission{{APIGroups: strings.Split(groups, ","), Resources: strings.Split(resources, ","), Verbs: []string{"get", "list"}, Scope: "namespaced"}}
}
func cluster(groups, resources string) []Permission {
	return []Permission{{APIGroups: strings.Split(groups, ","), Resources: strings.Split(resources, ","), Verbs: []string{"get", "list"}, Scope: "cluster"}}
}
