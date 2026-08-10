package rules

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
)

type IngressRule struct{}

func (IngressRule) Metadata() Metadata {
	permissions := namespaced("networking.k8s.io", "ingresses")
	permissions = append(permissions, namespaced("", "services,secrets")...)
	permissions = append(permissions, cluster("networking.k8s.io", "ingressclasses")...)
	return Metadata{ID: "ingress", Section: "Ingress", Description: "Ingress backend/TLS/IngressClass参照", Required: []string{"ingresses"}, Optional: []string{"services", "secrets", "ingressclasses"}, Permissions: permissions, Modes: []string{"all", "triage"}}
}

func (IngressRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	serviceExists := func(namespace, name string) bool {
		for i := range snapshot.Services {
			if snapshot.Services[i].Namespace == namespace && snapshot.Services[i].Name == name {
				return true
			}
		}
		return false
	}
	classExists := func(name string) bool {
		for i := range snapshot.IngressClasses {
			if snapshot.IngressClasses[i].Name == name {
				return true
			}
		}
		return false
	}
	for i := range snapshot.Ingresses {
		ingress := &snapshot.Ingresses[i]
		resource := ref("Ingress", ingress.Namespace, ingress.Name)
		services := []string{}
		if ingress.Spec.DefaultBackend != nil && ingress.Spec.DefaultBackend.Service != nil {
			services = append(services, ingress.Spec.DefaultBackend.Service.Name)
		}
		for _, rule := range ingress.Spec.Rules {
			if rule.HTTP == nil {
				continue
			}
			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service != nil {
					services = append(services, path.Backend.Service.Name)
				}
			}
		}
		for _, name := range services {
			if !snapshot.AvailableOrUntracked("services") {
				break
			}
			if !serviceExists(ingress.Namespace, name) {
				result = append(result, model.NewFinding(model.Issue, "K8S.INGRESS.MISSING_REFERENCE", "Ingress", resource, "MissingService", "service/"+name, fmt.Sprintf("Ingress %s: backend Service %sが存在しません", shortRef(ingress.Namespace, ingress.Name), name), 100))
			}
		}
		for _, tls := range ingress.Spec.TLS {
			if !snapshot.AvailableOrUntracked("secrets") {
				break
			}
			if tls.SecretName == "" {
				continue
			}
			secret, ok := snapshot.Secret(ingress.Namespace, tls.SecretName)
			if !ok {
				result = append(result, model.NewFinding(model.Issue, "K8S.INGRESS.MISSING_REFERENCE", "Ingress", resource, "MissingTLSSecret", "secret/"+tls.SecretName, fmt.Sprintf("Ingress %s: TLS Secret %sが存在しません", shortRef(ingress.Namespace, ingress.Name), tls.SecretName), 100))
				continue
			}
			if secret.Keys != nil {
				missing := []string{}
				for _, key := range []string{corev1.TLSCertKey, corev1.TLSPrivateKeyKey} {
					if _, exists := secret.Keys[key]; !exists {
						missing = append(missing, key)
					}
				}
				if len(missing) > 0 {
					result = append(result, model.NewFinding(model.Issue, "K8S.INGRESS.INVALID_TLS_SECRET", "Ingress", resource, "MissingTLSData", "secret/"+tls.SecretName+"/tls-data", fmt.Sprintf("Ingress %s: TLS Secret %sに%sがありません", shortRef(ingress.Namespace, ingress.Name), tls.SecretName, strings.Join(missing, ", ")), 100,
						model.Evidence{Kind: "reference", Key: "secret", Value: ref("Secret", ingress.Namespace, tls.SecretName)}))
				}
			}
		}
		if snapshot.AvailableOrUntracked("ingressclasses") && ingress.Spec.IngressClassName != nil && !classExists(*ingress.Spec.IngressClassName) {
			result = append(result, model.NewFinding(model.Warning, "K8S.INGRESS.CLASS_NOT_FOUND", "Ingress", resource, "IngressClassNotFound", "class/"+*ingress.Spec.IngressClassName, fmt.Sprintf("Ingress %s: IngressClass %sが存在しません", shortRef(ingress.Namespace, ingress.Name), *ingress.Spec.IngressClassName), 85))
		}
		if len(ingress.Status.LoadBalancer.Ingress) == 0 && elapsedSince(snapshot, ingress.CreationTimestamp.Time) >= 10*time.Minute {
			result = append(result, model.NewFinding(model.Candidate, "K8S.INGRESS.LOAD_BALANCER_PENDING", "Ingress", resource, "LoadBalancerPending", "load-balancer", fmt.Sprintf("Ingress %s: LoadBalancer addressがまだ割り当てられていません", shortRef(ingress.Namespace, ingress.Name)), 45))
		}
	}
	return result
}

type StorageRule struct{}

func (StorageRule) Metadata() Metadata {
	permissions := namespaced("", "persistentvolumeclaims")
	permissions = append(permissions, cluster("storage.k8s.io", "storageclasses")...)
	return Metadata{ID: "storage", Section: "PVC", Description: "PVC phaseとStorageClass binding mode", Required: []string{"pvcs"}, Optional: []string{"storageclasses"}, Permissions: permissions, Modes: []string{"all", "triage", "select"}}
}

func (StorageRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	classes := map[string]storagev1.VolumeBindingMode{}
	classExists := map[string]bool{}
	for i := range snapshot.StorageClasses {
		value := &snapshot.StorageClasses[i]
		classExists[value.Name] = true
		if value.VolumeBindingMode != nil {
			classes[value.Name] = *value.VolumeBindingMode
		}
	}
	for i := range snapshot.PersistentVolumeClaims {
		pvc := &snapshot.PersistentVolumeClaims[i]
		resource := ref("PersistentVolumeClaim", pvc.Namespace, pvc.Name)
		if pvc.Status.Phase == corev1.ClaimBound {
			for _, c := range pvc.Status.Conditions {
				if c.Status == corev1.ConditionTrue && (c.Type == corev1.PersistentVolumeClaimResizing || c.Type == corev1.PersistentVolumeClaimFileSystemResizePending) {
					result = append(result, model.NewFinding(model.Warning, "K8S.PVC.RESIZE_PENDING", "PVC", resource, string(c.Type), string(c.Type), fmt.Sprintf("PVC %s: %s", shortRef(pvc.Namespace, pvc.Name), c.Type), 75, model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message}))
				}
			}
			continue
		}
		if pvc.Status.Phase == corev1.ClaimLost {
			result = append(result, model.NewFinding(model.Issue, "K8S.PVC.LOST", "PVC", resource, "Lost", "phase", fmt.Sprintf("PVC %s: phase=Lost", shortRef(pvc.Namespace, pvc.Name)), 98))
			continue
		}
		className := ""
		if pvc.Spec.StorageClassName != nil {
			className = *pvc.Spec.StorageClassName
		}
		if pvc.Status.Phase == corev1.ClaimPending && !snapshot.AvailableOrUntracked("storageclasses") {
			continue // binding mode is unknown; do not turn an RBAC gap into a PVC warning
		}
		if pvc.Status.Phase == corev1.ClaimPending && className != "" && !classExists[className] {
			result = append(result, model.NewFinding(
				model.Issue, "K8S.PVC.STORAGE_CLASS_NOT_FOUND", "PVC", resource,
				"StorageClassNotFound", className,
				fmt.Sprintf("PVC %s: StorageClass %sが存在しません", shortRef(pvc.Namespace, pvc.Name), className), 100,
				model.Evidence{Kind: "spec", Key: "storageClassName", Value: className},
			))
			continue
		}
		if pvc.Status.Phase == corev1.ClaimPending && classes[className] == storagev1.VolumeBindingWaitForFirstConsumer {
			continue // normal delayed binding; scheduling rule correlates the consumer
		}
		result = append(result, model.NewFinding(model.Warning, "K8S.PVC.NOT_BOUND", "PVC", resource, string(pvc.Status.Phase), "phase", fmt.Sprintf("PVC %s: phase=%s", shortRef(pvc.Namespace, pvc.Name), pvc.Status.Phase), 75))
	}
	return result
}
