package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// UnusedFindings reports candidates only from successfully fetched resource
// sets. The caller must surface unavailable collections separately.
func UnusedFindings(snapshot *kube.Snapshot, excludeSystemNamespaces bool) []model.Finding {
	used := map[string]struct{}{}
	markPod := func(pod *corev1.Pod) {
		for _, dependency := range podDependencies(pod) {
			used[ref(dependency.Kind, dependency.Namespace, dependency.Name)] = struct{}{}
		}
		for _, dependency := range podPVCReferences(pod) {
			if dependency.ephemeral {
				used[ref("PersistentVolumeClaim", pod.Namespace, dependency.claimName)] = struct{}{}
			}
		}
	}
	markTemplate := func(namespace string, template corev1.PodTemplateSpec) {
		markPod(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: namespace}, Spec: template.Spec})
	}
	for i := range snapshot.Pods {
		markPod(&snapshot.Pods[i])
	}
	for i := range snapshot.Deployments {
		markTemplate(snapshot.Deployments[i].Namespace, snapshot.Deployments[i].Spec.Template)
	}
	for i := range snapshot.StatefulSets {
		markTemplate(snapshot.StatefulSets[i].Namespace, snapshot.StatefulSets[i].Spec.Template)
	}
	for i := range snapshot.DaemonSets {
		markTemplate(snapshot.DaemonSets[i].Namespace, snapshot.DaemonSets[i].Spec.Template)
	}
	for i := range snapshot.ReplicaSets {
		markTemplate(snapshot.ReplicaSets[i].Namespace, snapshot.ReplicaSets[i].Spec.Template)
	}
	for i := range snapshot.Jobs {
		markTemplate(snapshot.Jobs[i].Namespace, snapshot.Jobs[i].Spec.Template)
	}
	for i := range snapshot.CronJobs {
		markTemplate(snapshot.CronJobs[i].Namespace, snapshot.CronJobs[i].Spec.JobTemplate.Spec.Template)
	}
	for i := range snapshot.ServiceAccounts {
		account := &snapshot.ServiceAccounts[i]
		for _, secret := range account.Secrets {
			if secret.Name != "" {
				used[ref("Secret", account.Namespace, secret.Name)] = struct{}{}
			}
		}
		for _, secret := range account.ImagePullSecrets {
			if secret.Name != "" {
				used[ref("Secret", account.Namespace, secret.Name)] = struct{}{}
			}
		}
	}
	for i := range snapshot.Ingresses {
		ingress := &snapshot.Ingresses[i]
		for _, tls := range ingress.Spec.TLS {
			if tls.SecretName != "" {
				used[ref("Secret", ingress.Namespace, tls.SecretName)] = struct{}{}
			}
		}
	}
	type candidate struct{ kind, namespace, name string }
	candidates := []candidate{}
	keepNamespace := func(namespace string) bool {
		return !excludeSystemNamespaces || !strings.HasPrefix(namespace, "kube-")
	}
	if snapshot.Available("configmaps") {
		for i := range snapshot.ConfigMaps {
			value := &snapshot.ConfigMaps[i]
			if !keepNamespace(value.Namespace) || value.Name == "kube-root-ca.crt" {
				continue
			}
			candidates = append(candidates, candidate{"ConfigMap", value.Namespace, value.Name})
		}
	}
	if snapshot.Available("secrets") {
		for _, value := range snapshot.Secrets {
			if !keepNamespace(value.Namespace) || value.Type == "kubernetes.io/service-account-token" || value.Type == "helm.sh/release.v1" {
				continue
			}
			candidates = append(candidates, candidate{"Secret", value.Namespace, value.Name})
		}
	}
	if snapshot.Available("pvcs") {
		for i := range snapshot.PersistentVolumeClaims {
			value := &snapshot.PersistentVolumeClaims[i]
			if keepNamespace(value.Namespace) {
				candidates = append(candidates, candidate{"PersistentVolumeClaim", value.Namespace, value.Name})
			}
		}
	}
	if snapshot.Available("serviceaccounts") {
		for i := range snapshot.ServiceAccounts {
			value := &snapshot.ServiceAccounts[i]
			if !keepNamespace(value.Namespace) || value.Name == "default" {
				continue
			}
			candidates = append(candidates, candidate{"ServiceAccount", value.Namespace, value.Name})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].kind+candidates[i].namespace+candidates[i].name < candidates[j].kind+candidates[j].namespace+candidates[j].name
	})
	result := []model.Finding{}
	for _, value := range candidates {
		resource := ref(value.kind, value.namespace, value.name)
		if _, exists := used[resource]; exists {
			continue
		}
		result = append(result, model.NewFinding(model.Candidate, "K8S.UNUSED.CANDIDATE", "未使用候補", resource, "NoObservedReference", "unused", fmt.Sprintf("%s %s は、取得できたリソースの参照関係には現れませんでした。実際に未使用か確認してください", value.kind, shortRef(value.namespace, value.name)), 35))
	}
	return result
}
