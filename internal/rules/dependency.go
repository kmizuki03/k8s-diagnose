package rules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

type DependencyRule struct{}

func (DependencyRule) Metadata() Metadata {
	return Metadata{
		ID: "dependencies", Section: "関連リソース", Description: "Podの必須Secret/ConfigMap/PVC/ServiceAccount参照",
		Required:    []string{"pods", "configmaps", "secrets", "pvcs", "serviceaccounts"},
		Permissions: namespaced("", "pods,configmaps,secrets,persistentvolumeclaims,serviceaccounts"),
		Modes:       []string{"all", "triage", "select"},
	}
}

// PriorityClassDependencyRule checks cluster-scoped PriorityClass references
// separately so namespace-only access can retain namespaced dependency Coverage.
type PriorityClassDependencyRule struct{}

func (PriorityClassDependencyRule) Metadata() Metadata {
	return Metadata{
		ID: "priority-class-dependencies", Section: "関連リソース", Description: "PodのPriorityClass参照",
		Required: []string{"pods", "priorityclasses"}, Permissions: cluster("scheduling.k8s.io", "priorityclasses"),
		Modes: []string{"all", "triage", "select"},
	}
}

// RuntimeClassDependencyRule checks cluster-scoped RuntimeClass references.
type RuntimeClassDependencyRule struct{}

func (RuntimeClassDependencyRule) Metadata() Metadata {
	return Metadata{
		ID: "runtime-class-dependencies", Section: "関連リソース", Description: "PodのRuntimeClass参照",
		Required: []string{"pods", "runtimeclasses"}, Permissions: cluster("node.k8s.io", "runtimeclasses"),
		Modes: []string{"all", "triage", "select"},
	}
}

type objectDependency struct {
	Kind, Namespace, Name, Key, Source string
	Optional                           bool
}

func (DependencyRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	return evaluateDependencies(snapshot, map[string]bool{
		"ConfigMap": true, "Secret": true, "PersistentVolumeClaim": true, "ServiceAccount": true,
	})
}

func (PriorityClassDependencyRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	return evaluateDependencies(snapshot, map[string]bool{"PriorityClass": true})
}

func (RuntimeClassDependencyRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	return evaluateDependencies(snapshot, map[string]bool{"RuntimeClass": true})
}

func evaluateDependencies(snapshot *kube.Snapshot, allowed map[string]bool) []model.Finding {
	findings := []model.Finding{}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		dependencies := podDependencies(pod)
		// A required reference wins when the same object/key is also optional.
		merged := map[string]objectDependency{}
		for _, dependency := range dependencies {
			if !allowed[dependency.Kind] {
				continue
			}
			key := dependency.Kind + "\x00" + dependency.Namespace + "\x00" + dependency.Name + "\x00" + dependency.Key
			previous, exists := merged[key]
			if !exists || previous.Optional && !dependency.Optional {
				merged[key] = dependency
			}
		}
		keys := make([]string, 0, len(merged))
		for key := range merged {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			dependency := merged[key]
			if dependency.Optional {
				continue
			}
			exists, keyExists := dependencyExists(snapshot, dependency)
			ephemeral := strings.HasPrefix(dependency.Source, "ephemeralContainer/")
			if !exists {
				if dependency.Source == "imagePullSecrets" {
					findings = append(findings, model.NewFinding(
						model.Warning, "K8S.DEPENDENCY.MISSING_IMAGE_PULL_SECRET", "関連リソース",
						ref(dependency.Kind, dependency.Namespace, dependency.Name), "MissingImagePullSecret", dependency.Name,
						fmt.Sprintf("Pod %s: imagePullSecret %sが存在しません (Node資格情報等でpullできる場合があるため警告扱い)", shortRef(pod.Namespace, pod.Name), dependency.Name), 85,
						model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
						model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
					))
					continue
				}
				if ephemeral {
					findings = append(findings, model.NewFinding(
						model.Warning, "K8S.DEPENDENCY.EPHEMERAL_MISSING_OBJECT", "関連リソース",
						ref(dependency.Kind, dependency.Namespace, dependency.Name), "EphemeralDependencyNotFound", dependency.Kind+"/"+dependency.Name,
						fmt.Sprintf("Pod %s: Ephemeral Containerが参照する%s %sが存在しません (既存Podの稼働には影響しません)", shortRef(pod.Namespace, pod.Name), dependency.Kind, dependency.Name), 85,
						model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
						model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
					))
					continue
				}
				findings = append(findings, model.NewFinding(
					model.Issue, "K8S.DEPENDENCY.MISSING_OBJECT", "関連リソース",
					ref(dependency.Kind, dependency.Namespace, dependency.Name), "NotFound", dependency.Kind+"/"+dependency.Name,
					fmt.Sprintf("Pod %s: 必須%s %sが存在しません", shortRef(pod.Namespace, pod.Name), dependency.Kind, dependency.Name), 100,
					model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
					model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
				))
				continue
			}
			if dependency.Key != "" && !keyExists {
				if ephemeral {
					findings = append(findings, model.NewFinding(
						model.Warning, "K8S.DEPENDENCY.EPHEMERAL_MISSING_KEY", "関連リソース",
						ref(dependency.Kind, dependency.Namespace, dependency.Name), "EphemeralMissingKey", dependency.Name+"/"+dependency.Key,
						fmt.Sprintf("Pod %s: Ephemeral Containerが参照する%s %sにキー %q が存在しません (既存Podの稼働には影響しません)", shortRef(pod.Namespace, pod.Name), dependency.Kind, dependency.Name, dependency.Key), 85,
						model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
						model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
					))
					continue
				}
				findings = append(findings, model.NewFinding(
					model.Issue, "K8S.DEPENDENCY.MISSING_KEY", "関連リソース",
					ref(dependency.Kind, dependency.Namespace, dependency.Name), "MissingKey", dependency.Name+"/"+dependency.Key,
					fmt.Sprintf("Pod %s: 必須%s %sにキー %q が存在しません", shortRef(pod.Namespace, pod.Name), dependency.Kind, dependency.Name, dependency.Key), 100,
					model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
					model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
				))
			}
		}
	}
	return findings
}

func podDependencies(pod *corev1.Pod) []objectDependency {
	result := []objectDependency{}
	addContainer := func(container corev1.Container, sourcePrefix string) {
		for _, from := range container.EnvFrom {
			if from.ConfigMapRef != nil {
				result = append(result, objectDependency{"ConfigMap", pod.Namespace, from.ConfigMapRef.Name, "", sourcePrefix + ".envFrom.configMapRef", boolValue(from.ConfigMapRef.Optional, false)})
			}
			if from.SecretRef != nil {
				result = append(result, objectDependency{"Secret", pod.Namespace, from.SecretRef.Name, "", sourcePrefix + ".envFrom.secretRef", boolValue(from.SecretRef.Optional, false)})
			}
		}
		for _, env := range container.Env {
			if env.ValueFrom == nil {
				continue
			}
			if value := env.ValueFrom.ConfigMapKeyRef; value != nil {
				result = append(result, objectDependency{"ConfigMap", pod.Namespace, value.Name, value.Key, sourcePrefix + ".env." + env.Name, boolValue(value.Optional, false)})
			}
			if value := env.ValueFrom.SecretKeyRef; value != nil {
				result = append(result, objectDependency{"Secret", pod.Namespace, value.Name, value.Key, sourcePrefix + ".env." + env.Name, boolValue(value.Optional, false)})
			}
		}
	}
	for _, container := range pod.Spec.InitContainers {
		addContainer(container, "initContainer/"+container.Name)
	}
	for _, container := range pod.Spec.Containers {
		addContainer(container, "container/"+container.Name)
	}
	for _, container := range pod.Spec.EphemeralContainers {
		addContainer(corev1.Container(container.EphemeralContainerCommon), "ephemeralContainer/"+container.Name)
	}
	for _, volume := range pod.Spec.Volumes {
		addVolumeSecret := func(reference *corev1.LocalObjectReference, source string) {
			if reference == nil || reference.Name == "" {
				return
			}
			result = append(result, objectDependency{"Secret", pod.Namespace, reference.Name, "", "volume/" + volume.Name + "." + source, false})
		}
		if volume.ConfigMap != nil {
			if len(volume.ConfigMap.Items) == 0 {
				result = append(result, objectDependency{"ConfigMap", pod.Namespace, volume.ConfigMap.Name, "", "volume/" + volume.Name, boolValue(volume.ConfigMap.Optional, false)})
			} else {
				for _, item := range volume.ConfigMap.Items {
					result = append(result, objectDependency{"ConfigMap", pod.Namespace, volume.ConfigMap.Name, item.Key, "volume/" + volume.Name, boolValue(volume.ConfigMap.Optional, false)})
				}
			}
		}
		if volume.Secret != nil {
			if len(volume.Secret.Items) == 0 {
				result = append(result, objectDependency{"Secret", pod.Namespace, volume.Secret.SecretName, "", "volume/" + volume.Name, boolValue(volume.Secret.Optional, false)})
			} else {
				for _, item := range volume.Secret.Items {
					result = append(result, objectDependency{"Secret", pod.Namespace, volume.Secret.SecretName, item.Key, "volume/" + volume.Name, boolValue(volume.Secret.Optional, false)})
				}
			}
		}
		if volume.PersistentVolumeClaim != nil {
			result = append(result, objectDependency{"PersistentVolumeClaim", pod.Namespace, volume.PersistentVolumeClaim.ClaimName, "", "volume/" + volume.Name, false})
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.ConfigMap != nil {
					if len(source.ConfigMap.Items) == 0 {
						result = append(result, objectDependency{"ConfigMap", pod.Namespace, source.ConfigMap.Name, "", "projected/" + volume.Name, boolValue(source.ConfigMap.Optional, false)})
					} else {
						for _, item := range source.ConfigMap.Items {
							result = append(result, objectDependency{"ConfigMap", pod.Namespace, source.ConfigMap.Name, item.Key, "projected/" + volume.Name, boolValue(source.ConfigMap.Optional, false)})
						}
					}
				}
				if source.Secret != nil {
					if len(source.Secret.Items) == 0 {
						result = append(result, objectDependency{"Secret", pod.Namespace, source.Secret.Name, "", "projected/" + volume.Name, boolValue(source.Secret.Optional, false)})
					} else {
						for _, item := range source.Secret.Items {
							result = append(result, objectDependency{"Secret", pod.Namespace, source.Secret.Name, item.Key, "projected/" + volume.Name, boolValue(source.Secret.Optional, false)})
						}
					}
				}
			}
		}
		if volume.CSI != nil {
			addVolumeSecret(volume.CSI.NodePublishSecretRef, "csi.nodePublishSecretRef")
		}
		if volume.RBD != nil {
			addVolumeSecret(volume.RBD.SecretRef, "rbd.secretRef")
		}
		if volume.Cinder != nil {
			addVolumeSecret(volume.Cinder.SecretRef, "cinder.secretRef")
		}
		if volume.CephFS != nil {
			addVolumeSecret(volume.CephFS.SecretRef, "cephfs.secretRef")
		}
		if volume.FlexVolume != nil {
			addVolumeSecret(volume.FlexVolume.SecretRef, "flexVolume.secretRef")
		}
		if volume.ISCSI != nil {
			addVolumeSecret(volume.ISCSI.SecretRef, "iscsi.secretRef")
		}
		if volume.ScaleIO != nil {
			addVolumeSecret(volume.ScaleIO.SecretRef, "scaleIO.secretRef")
		}
		if volume.StorageOS != nil {
			addVolumeSecret(volume.StorageOS.SecretRef, "storageOS.secretRef")
		}
		if volume.AzureFile != nil && volume.AzureFile.SecretName != "" {
			result = append(result, objectDependency{"Secret", pod.Namespace, volume.AzureFile.SecretName, "", "volume/" + volume.Name + ".azureFile.secretName", false})
		}
	}
	for _, secret := range pod.Spec.ImagePullSecrets {
		result = append(result, objectDependency{"Secret", pod.Namespace, secret.Name, "", "imagePullSecrets", false})
	}
	serviceAccount := pod.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}
	result = append(result, objectDependency{"ServiceAccount", pod.Namespace, serviceAccount, "", "serviceAccountName", false})
	if pod.Spec.PriorityClassName != "" {
		result = append(result, objectDependency{"PriorityClass", "", pod.Spec.PriorityClassName, "", "priorityClassName", false})
	}
	if pod.Spec.RuntimeClassName != nil && *pod.Spec.RuntimeClassName != "" {
		result = append(result, objectDependency{"RuntimeClass", "", *pod.Spec.RuntimeClassName, "", "runtimeClassName", false})
	}
	return result
}

func dependencyExists(snapshot *kube.Snapshot, dependency objectDependency) (bool, bool) {
	switch dependency.Kind {
	case "Secret":
		secret, ok := snapshot.Secret(dependency.Namespace, dependency.Name)
		if !ok {
			return false, false
		}
		if dependency.Key == "" {
			return true, true
		}
		_, keyExists := secret.Keys[dependency.Key]
		return true, keyExists
	case "ConfigMap":
		value, ok := snapshot.ConfigMap(dependency.Namespace, dependency.Name)
		if !ok {
			return false, false
		}
		if dependency.Key == "" {
			return true, true
		}
		_, data := value.Data[dependency.Key]
		_, binary := value.BinaryData[dependency.Key]
		return true, data || binary
	case "PersistentVolumeClaim":
		for i := range snapshot.PersistentVolumeClaims {
			value := &snapshot.PersistentVolumeClaims[i]
			if value.Namespace == dependency.Namespace && value.Name == dependency.Name {
				return true, true
			}
		}
	case "ServiceAccount":
		for i := range snapshot.ServiceAccounts {
			value := &snapshot.ServiceAccounts[i]
			if value.Namespace == dependency.Namespace && value.Name == dependency.Name {
				return true, true
			}
		}
	case "PriorityClass":
		for i := range snapshot.PriorityClasses {
			if snapshot.PriorityClasses[i].Name == dependency.Name {
				return true, true
			}
		}
	case "RuntimeClass":
		for i := range snapshot.RuntimeClasses {
			if snapshot.RuntimeClasses[i].Name == dependency.Name {
				return true, true
			}
		}
	}
	return false, false
}
