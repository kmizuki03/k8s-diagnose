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
		ID: "dependencies", Section: "関連リソース", Description: "Podが必須参照するSecret・ConfigMap・PVC・ServiceAccount",
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
		ID: "priority-class-dependencies", Section: "関連リソース", Description: "Podが参照するPriorityClass",
		Required: []string{"pods", "priorityclasses"}, Permissions: cluster("scheduling.k8s.io", "priorityclasses"),
		Modes: []string{"all", "triage", "select"},
	}
}

// RuntimeClassDependencyRule checks cluster-scoped RuntimeClass references.
type RuntimeClassDependencyRule struct{}

func (RuntimeClassDependencyRule) Metadata() Metadata {
	return Metadata{
		ID: "runtime-class-dependencies", Section: "関連リソース", Description: "Podが参照するRuntimeClass",
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
			// The same ConfigMap key has different semantics depending on the
			// consumer: configMapKeyRef reads Data only, while a volume item may
			// also project BinaryData. Keep those references separate so a valid
			// binary volume cannot hide a missing environment-variable value.
			key := dependency.Kind + "\x00" + dependency.Namespace + "\x00" + dependency.Name + "\x00" + dependency.Key
			if configMapDataOnlyReference(dependency) {
				key += "\x00data-only"
			}
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
				if finding, ok := optionalDependencyFinding(snapshot, pod, dependency); ok {
					findings = append(findings, finding)
				}
				continue
			}
			exists, keyExists := dependencyExists(snapshot, dependency)
			ephemeral := strings.HasPrefix(dependency.Source, "ephemeralContainer/")
			if !exists {
				if dependency.Source == "imagePullSecrets" {
					findings = append(findings, model.NewFinding(
						model.Warning, "K8S.DEPENDENCY.MISSING_IMAGE_PULL_SECRET", "関連リソース",
						ref(dependency.Kind, dependency.Namespace, dependency.Name), "MissingImagePullSecret", dependency.Name,
						fmt.Sprintf("Pod %s がimagePullSecretsで参照している %s は、Kubernetesクラスタに存在しません（Secretリソース自体が未作成か、すでに削除されています）。ただし、Node側の資格情報などでイメージを取得できる可能性があるため、警告として扱います", shortRef(pod.Namespace, pod.Name), dependencyObjectLabel(dependency)), 85,
						model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
						model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
						missingDependencyEvidence(dependency),
					))
					continue
				}
				if ephemeral {
					findings = append(findings, model.NewFinding(
						model.Warning, "K8S.DEPENDENCY.EPHEMERAL_MISSING_OBJECT", "関連リソース",
						ref(dependency.Kind, dependency.Namespace, dependency.Name), "EphemeralDependencyNotFound", dependency.Kind+"/"+dependency.Name,
						fmt.Sprintf("Pod %s の一時デバッグ用コンテナ（Ephemeral Container）が参照する %s は、Kubernetesクラスタに存在しません（リソース自体が未作成か、すでに削除されています）。既存コンテナの稼働には影響しません", shortRef(pod.Namespace, pod.Name), dependencyObjectLabel(dependency)), 85,
						model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
						model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
						missingDependencyEvidence(dependency),
					))
					continue
				}
				findings = append(findings, model.NewFinding(
					model.Issue, "K8S.DEPENDENCY.MISSING_OBJECT", "関連リソース",
					ref(dependency.Kind, dependency.Namespace, dependency.Name), "NotFound", dependency.Kind+"/"+dependency.Name,
					fmt.Sprintf("Pod %s が %s で必須参照している %s は、Kubernetesクラスタに存在しません（リソース自体が未作成か、すでに削除されています）", shortRef(pod.Namespace, pod.Name), dependency.Source, dependencyObjectLabel(dependency)), 100,
					model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
					model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
					missingDependencyEvidence(dependency),
				))
				continue
			}
			if dependency.Key != "" && !keyExists {
				if ephemeral {
					findings = append(findings, model.NewFinding(
						model.Warning, "K8S.DEPENDENCY.EPHEMERAL_MISSING_KEY", "関連リソース",
						ref(dependency.Kind, dependency.Namespace, dependency.Name), "EphemeralMissingKey", dependency.Name+"/"+dependency.Key,
						fmt.Sprintf("Pod %s の一時デバッグ用コンテナ（Ephemeral Container）が参照する %s %q には、キー %q が存在しません。既存コンテナの稼働には影響しません", shortRef(pod.Namespace, pod.Name), dependency.Kind, dependency.Name, dependency.Key), 85,
						model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source},
						model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
					))
					continue
				}
				findings = append(findings, model.NewFinding(
					model.Issue, "K8S.DEPENDENCY.MISSING_KEY", "関連リソース",
					ref(dependency.Kind, dependency.Namespace, dependency.Name), "MissingKey", dependency.Name+"/"+dependency.Key,
					fmt.Sprintf("Pod %s が必須として参照している %s %q には、キー %q が存在しません", shortRef(pod.Namespace, pod.Name), dependency.Kind, dependency.Name, dependency.Key), 100,
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

// optionalDependencyFinding reports an optional reference whose target is not
// actually there. optional:true tells kubelet to start the container regardless,
// so nothing fails, nothing restarts, and no event is recorded — the environment
// variable or file simply never exists and the container runs as if that piece
// of configuration had never been written. Marking a reference optional is how a
// mistyped key stops being a startup error and becomes silence.
//
// A missing optional object is reported as a low-confidence candidate rather
// than hidden: Kubernetes allows it, but operators still need to know that the
// referenced value or file does not exist. A missing key in an object that is
// present is a stronger typo signal and gets a separate candidate.
func optionalDependencyFinding(snapshot *kube.Snapshot, pod *corev1.Pod, dependency objectDependency) (model.Finding, bool) {
	exists, keyExists := dependencyExists(snapshot, dependency)
	if !exists {
		return model.NewFinding(
			model.Candidate, "K8S.DEPENDENCY.OPTIONAL_OBJECT_MISSING", "関連リソース",
			ref(dependency.Kind, dependency.Namespace, dependency.Name), "OptionalDependencyNotFound",
			dependency.Kind+"/"+dependency.Name+"/object",
			fmt.Sprintf("Pod %s は %s で %s を optional: true として参照していますが、そのリソース自体はKubernetesクラスタに存在しません。Podは参照先なしでも起動できますが、設定が意図どおりか確認してください",
				shortRef(pod.Namespace, pod.Name), dependency.Source, dependencyObjectLabel(dependency)), 45,
			model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source + "（optional: true）"},
			model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
			missingDependencyEvidence(dependency),
			model.Evidence{Kind: "decision", Key: "optional", Value: "optional: true のため、参照先リソースがなくてもkubeletはPodの起動を継続します"},
		), true
	}
	if dependency.Kind != "ConfigMap" && dependency.Kind != "Secret" || dependency.Key == "" || keyExists {
		return model.Finding{}, false
	}
	return model.NewFinding(
		model.Candidate, "K8S.DEPENDENCY.OPTIONAL_KEY_MISSING", "関連リソース",
		ref(dependency.Kind, dependency.Namespace, dependency.Name), "OptionalKeyMissing",
		dependency.Kind+"/"+dependency.Name+"/"+dependency.Key,
		fmt.Sprintf("Pod %s が %s で参照するキー %q は、%s %s に存在しません。%s自体は存在するためキー名の誤りが疑われますが、optional: true のため起動は成功し、この値は設定されないままです",
			shortRef(pod.Namespace, pod.Name), dependency.Source, dependency.Key, dependency.Kind, shortRef(dependency.Namespace, dependency.Name), dependency.Kind), 50,
		model.Evidence{Kind: "reference", Key: "source", Value: dependency.Source + "（optional: true）"},
		model.Evidence{Kind: "reference", Key: "pod", Value: ref("Pod", pod.Namespace, pod.Name)},
		model.Evidence{Kind: "reference", Key: "availableKeys", Value: dependencyKeySummary(snapshot, dependency)},
		model.Evidence{Kind: "decision", Key: "optional", Value: "optional: true のため、kubeletは値を設定しないままコンテナを起動します。Podの状態にもEventにも痕跡が残りません"},
	), true
}

func dependencyObjectLabel(dependency objectDependency) string {
	return dependency.Kind + " " + shortRef(dependency.Namespace, dependency.Name)
}

func missingDependencyEvidence(dependency objectDependency) model.Evidence {
	return model.Evidence{
		Kind: "decision", Key: "objectNotFound",
		Value: fmt.Sprintf("%s一覧の取得には成功しましたが、%s と一致するリソースは0件でした", dependency.Kind, shortRef(dependency.Namespace, dependency.Name)),
	}
}

// dependencyKeySummary lists what the object does provide, which is what turns
// "the key is missing" into a name the operator can compare against.
func dependencyKeySummary(snapshot *kube.Snapshot, dependency objectDependency) string {
	keys := map[string]struct{}{}
	ignoredBinary := map[string]struct{}{}
	switch dependency.Kind {
	case "ConfigMap":
		if value, ok := snapshot.ConfigMap(dependency.Namespace, dependency.Name); ok {
			for key := range value.Data {
				keys[key] = struct{}{}
			}
			if !configMapDataOnlyReference(dependency) {
				for key := range value.BinaryData {
					keys[key] = struct{}{}
				}
			} else {
				for key := range value.BinaryData {
					ignoredBinary[key] = struct{}{}
				}
			}
		}
	case "Secret":
		if value, ok := snapshot.Secret(dependency.Namespace, dependency.Name); ok {
			for key := range value.Keys {
				keys[key] = struct{}{}
			}
		}
	}
	label := dependency.Kind + " に定義されたキー"
	if configMapDataOnlyReference(dependency) {
		label = "ConfigMapのdataに定義されたキー"
	}
	result := label + ": なし（0件）"
	if len(keys) > 0 {
		result = label + ": " + summarizeStrings(sortedStringSet(keys), 10)
	}
	if len(ignoredBinary) > 0 {
		result += "。binaryDataのキー " + summarizeStrings(sortedStringSet(ignoredBinary), 10) + " はconfigMapKeyRefから環境変数として参照できません"
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
		if configMapDataOnlyReference(dependency) {
			return true, data
		}
		_, binary := value.BinaryData[dependency.Key]
		return true, data || binary
	case "PersistentVolumeClaim":
		if _, ok := snapshot.PersistentVolumeClaim(dependency.Namespace, dependency.Name); ok {
			return true, true
		}
	case "ServiceAccount":
		if _, ok := snapshot.ServiceAccount(dependency.Namespace, dependency.Name); ok {
			return true, true
		}
	case "PriorityClass":
		if _, ok := snapshot.PriorityClass(dependency.Name); ok {
			return true, true
		}
	case "RuntimeClass":
		if _, ok := snapshot.RuntimeClass(dependency.Name); ok {
			return true, true
		}
	}
	return false, false
}

// configMapDataOnlyReference identifies ConfigMapKeySelector consumers. The
// source strings are generated in podDependencies; envFrom has no Key and does
// not reach this distinction. Volume and projected-volume items may consume
// BinaryData, but env[].valueFrom.configMapKeyRef cannot.
func configMapDataOnlyReference(dependency objectDependency) bool {
	return dependency.Kind == "ConfigMap" && dependency.Key != "" && strings.Contains(dependency.Source, ".env.")
}
