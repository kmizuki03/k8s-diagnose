package rules

import (
	"context"
	"fmt"
	"sort"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

// configMapObjectLimitBytes is the size a single API object may reach. The API
// server refuses anything larger, so a ConfigMap already in the cluster is
// always under it — the value of measuring is warning before the *next* update
// is the one that gets rejected.
const configMapObjectLimitBytes = 1 << 20

// configMapSizeWarnPercent is how full a ConfigMap must be before its remaining
// headroom is worth reporting.
const configMapSizeWarnPercent = 90

// ConfigMapRule diagnoses the ConfigMap itself. Every other ConfigMap check in
// this tool is anchored on a Pod and asks only whether a reference resolves
// (DependencyRule) or whether anything references it at all (unused). Neither
// notices a ConfigMap that resolves perfectly and still fails to reach the
// container, which is what this rule covers.
type ConfigMapRule struct{}

func (ConfigMapRule) Metadata() Metadata {
	return Metadata{
		ID: "configmaps", Section: "ConfigMap",
		Description: "ConfigMap自体の状態と、解決できてもコンテナへ反映されない設定",
		Required:    []string{"configmaps"},
		Optional:    []string{"pods", "secrets"},
		Permissions: namespaced("", "configmaps,pods,secrets"),
		Modes:       []string{"all", "triage", "select"},
	}
}

func (ConfigMapRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.ConfigMaps {
		if finding, ok := configMapSizeFinding(&snapshot.ConfigMaps[i]); ok {
			result = append(result, finding)
		}
	}
	if !snapshot.AvailableOrUntracked("pods") {
		return result
	}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		result = append(result, configMapEnvShadowFindings(pod, snapshot)...)
		result = append(result, configMapSubPathFindings(pod, snapshot)...)
	}
	return result
}

// envSupply is one environment variable a container receives from an envFrom
// source, in the order kubelet applies them.
type envSupply struct {
	name   string
	kind   string
	object string
	value  string
	// known is false for Secret values, which the snapshot deliberately never
	// holds: the collision is still visible, the values just cannot be compared.
	known bool
}

// containerEnvSupplies expands every envFrom source of a container into the
// variables it contributes, preserving source order. Current Kubernetes uses
// relaxed environment-variable validation for envFrom keys. ConfigMap
// binaryData is intentionally absent: kubelet's envFrom expansion reads Data
// only; binaryData is available to volume projections, not environment vars.
func containerEnvSupplies(container corev1.Container, namespace string, snapshot *kube.Snapshot) []envSupply {
	supplies := []envSupply{}
	for _, source := range container.EnvFrom {
		switch {
		case source.ConfigMapRef != nil:
			configMap, ok := snapshot.ConfigMap(namespace, source.ConfigMapRef.Name)
			if !ok {
				continue
			}
			for _, key := range sortedMapKeys(configMap.Data) {
				supplies = append(supplies, envSupply{source.Prefix + key, "ConfigMap", configMap.Name, configMap.Data[key], true})
			}
		case source.SecretRef != nil:
			secret, ok := snapshot.Secret(namespace, source.SecretRef.Name)
			if !ok {
				continue
			}
			for _, key := range sortedMapKeys(secret.Keys) {
				supplies = append(supplies, envSupply{source.Prefix + key, "Secret", secret.Name, "", false})
			}
		}
	}
	// Precedence follows the envFrom order the entries were appended in. Keys
	// within one source are sorted only so the emitted findings stay stable
	// across runs, since map iteration is unordered.
	return supplies
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// configMapEnvShadowFindings reports a ConfigMap key that resolves, is a usable
// variable name, and still never reaches the container because a later source
// sets the same variable. Kubernetes states the precedence on Container.EnvFrom:
// the last source wins, and an env entry beats every envFrom source.
//
// This is invisible in the manifest. Two envFrom ConfigMaps overlapping on one
// key looks fine in the Pod spec — you have to open both ConfigMaps to see it —
// which is why the value in the ConfigMap and the value in the container can
// disagree with nothing anywhere reporting a problem.
//
// Overriding defaults on purpose is a normal pattern, so this stays a candidate
// and is raised only when the two values actually differ. Where a value cannot
// be read (Secret data is never collected, binaryData is not text) the collision
// is still reported, because it cannot be ruled out.
func configMapEnvShadowFindings(pod *corev1.Pod, snapshot *kube.Snapshot) []model.Finding {
	result := []model.Finding{}
	forEachPodContainer(pod, func(container corev1.Container, label string) {
		// A single envFrom source with no env entries cannot collide with
		// anything, which is the shape of almost every container in a real
		// cluster. Checking that first keeps the rule from expanding every
		// referenced ConfigMap on the whole snapshot for nothing.
		if len(container.EnvFrom) == 0 || len(container.EnvFrom) == 1 && len(container.Env) == 0 {
			return
		}
		supplies := containerEnvSupplies(container, pod.Namespace, snapshot)
		if len(supplies) == 0 {
			return
		}
		explicit := map[string]corev1.EnvVar{}
		for _, env := range container.Env {
			explicit[env.Name] = env
		}
		last := map[string]int{}
		for index, supply := range supplies {
			last[supply.name] = index
		}
		for index, supply := range supplies {
			if supply.kind != "ConfigMap" {
				continue
			}
			winner, differs := envShadowWinner(supply, index, last, supplies, explicit)
			if winner == "" || !differs {
				continue
			}
			result = append(result, model.NewFinding(
				model.Candidate, "K8S.CONFIGMAP.ENV_KEY_SHADOWED", "ConfigMap",
				ref("ConfigMap", pod.Namespace, supply.object), "EnvKeyShadowed",
				"env-shadow/"+pod.Name+"/"+container.Name+"/"+supply.name,
				fmt.Sprintf("ConfigMap %s は環境変数 %q を設定しますが、%s の %s では %s が同じ変数を後から設定するため、ConfigMapの値はコンテナに渡りません。意図的な上書きであれば設定どおりです",
					shortRef(pod.Namespace, supply.object), supply.name, shortRef(pod.Namespace, pod.Name), label, winner), 45,
				model.Evidence{Kind: "configMap", Key: "envFrom", Value: fmt.Sprintf("ConfigMap %s が %q を設定", shortRef(pod.Namespace, supply.object), supply.name)},
				model.Evidence{Kind: "pod", Key: "override", Value: fmt.Sprintf("%s の %s では %s が優先されます", shortRef(pod.Namespace, pod.Name), label, winner)},
				model.Evidence{Kind: "decision", Key: "precedence", Value: "Kubernetesは、同じ変数名が複数のenvFromにある場合は後のソースを、envに書かれている場合はenvを優先します"},
			))
		}
	})
	return result
}

// envShadowWinner names whatever overrides this supply and reports whether the
// effective value actually changes. A source that sets the identical value is
// not worth anyone's attention.
func envShadowWinner(supply envSupply, index int, last map[string]int, supplies []envSupply, explicit map[string]corev1.EnvVar) (string, bool) {
	if env, overridden := explicit[supply.name]; overridden {
		if env.ValueFrom != nil {
			return "env の " + env.Name + "（valueFrom）", true
		}
		return fmt.Sprintf("env の %s", env.Name), !supply.known || env.Value != supply.value
	}
	winnerIndex, ok := last[supply.name]
	if !ok || winnerIndex <= index {
		return "", false
	}
	winner := supplies[winnerIndex]
	label := fmt.Sprintf("後続の envFrom（%s %s）", winner.kind, winner.object)
	if !supply.known || !winner.known {
		return label, true
	}
	return label, winner.value != supply.value
}

func configMapDataBytes(configMap *corev1.ConfigMap) int {
	total := 0
	for key, value := range configMap.Data {
		total += len(key) + len(value)
	}
	for key, value := range configMap.BinaryData {
		total += len(key) + len(value)
	}
	return total
}

func configMapSizeFinding(configMap *corev1.ConfigMap) (model.Finding, bool) {
	total := configMapDataBytes(configMap)
	percent := total * 100 / configMapObjectLimitBytes
	if percent < configMapSizeWarnPercent {
		return model.Finding{}, false
	}
	return model.NewFinding(
		model.Warning, "K8S.CONFIGMAP.SIZE_NEAR_LIMIT", "ConfigMap",
		ref("ConfigMap", configMap.Namespace, configMap.Name), "SizeNearLimit", "size",
		fmt.Sprintf("ConfigMap %s のデータ量は約%dKiBで、1オブジェクトの上限1MiBの%d%%に達しています。これ以上キーを追加したり値を大きくしたりする更新は、APIサーバに拒否される可能性があります",
			shortRef(configMap.Namespace, configMap.Name), total/1024, percent), 70,
		model.Evidence{Kind: "configMap", Key: "data", Value: fmt.Sprintf("data %d件・binaryData %d件の合計 %dバイト", len(configMap.Data), len(configMap.BinaryData), total)},
		model.Evidence{Kind: "decision", Key: "limit", Value: fmt.Sprintf("1オブジェクトの上限 %dバイトに対して %d%%", configMapObjectLimitBytes, percent)},
	), true
}

// configMapSubPathFindings reports ConfigMap volumes mounted with subPath.
// Kubernetes refreshes a ConfigMap volume in place, but a subPath mount is
// resolved once at container start and never updated, so editing the ConfigMap
// changes nothing inside the container until the Pod is recreated. Mounting a
// single file this way is a deliberate and common pattern, so this is only ever
// a candidate — it exists because "I updated the ConfigMap and nothing
// happened" has no other visible cause.
func configMapSubPathFindings(pod *corev1.Pod, snapshot *kube.Snapshot) []model.Finding {
	volumes := map[string]string{}
	for _, volume := range pod.Spec.Volumes {
		if volume.ConfigMap != nil {
			volumes[volume.Name] = volume.ConfigMap.Name
		}
	}
	if len(volumes) == 0 {
		return nil
	}
	result := []model.Finding{}
	forEachPodContainer(pod, func(container corev1.Container, label string) {
		for _, mount := range container.VolumeMounts {
			name, isConfigMap := volumes[mount.Name]
			if !isConfigMap || mount.SubPath == "" && mount.SubPathExpr == "" {
				continue
			}
			if _, exists := snapshot.ConfigMap(pod.Namespace, name); !exists {
				continue
			}
			subPath := mount.SubPath
			if subPath == "" {
				subPath = mount.SubPathExpr
			}
			result = append(result, model.NewFinding(
				model.Candidate, "K8S.CONFIGMAP.SUBPATH_NOT_UPDATED", "ConfigMap",
				ref("Pod", pod.Namespace, pod.Name), "SubPathNotUpdated",
				"subpath/"+container.Name+"/"+mount.Name+"/"+subPath,
				fmt.Sprintf("Pod %s の %s は、ConfigMap %s を subPath %q でマウントしています。subPathマウントはConfigMapを更新してもファイルが差し替わらないため、変更を反映するにはPodの再作成が必要です。1ファイルだけをマウントする意図であれば設定どおりです",
					shortRef(pod.Namespace, pod.Name), label, shortRef(pod.Namespace, name), subPath), 45,
				model.Evidence{Kind: "pod", Key: "volumeMounts", Value: fmt.Sprintf("%s の %s: mountPath %q, subPath %q", label, mount.Name, mount.MountPath, subPath)},
				model.Evidence{Kind: "configMap", Key: "name", Value: "参照先ConfigMap: " + shortRef(pod.Namespace, name)},
				model.Evidence{Kind: "decision", Key: "propagation", Value: "subPathを使わないマウントはkubeletが自動更新しますが、subPathはコンテナ起動時に解決されたまま固定されます"},
			))
		}
	})
	return result
}

// forEachPodContainer visits every container that can consume a ConfigMap,
// labelled the way the rest of the diagnosis names them.
func forEachPodContainer(pod *corev1.Pod, visit func(corev1.Container, string)) {
	for _, container := range pod.Spec.InitContainers {
		visit(container, "initContainer/"+container.Name)
	}
	for _, container := range pod.Spec.Containers {
		visit(container, "container/"+container.Name)
	}
	for _, container := range pod.Spec.EphemeralContainers {
		visit(corev1.Container(container.EphemeralContainerCommon), "ephemeralContainer/"+container.Name)
	}
}
