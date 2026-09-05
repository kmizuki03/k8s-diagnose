package rules

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

// RuntimeDependencyRule reports dependency risks encoded in Pod environment
// values which Kubernetes itself does not resolve or validate.
type RuntimeDependencyRule struct{}

func (RuntimeDependencyRule) Metadata() Metadata {
	return Metadata{
		ID: "runtime-dependencies", Section: "関連リソース", Description: "環境変数に記述されたService名・設定反映・PVC実行権限",
		Required: []string{"pods", "services"}, Optional: []string{"configmaps"},
		Permissions: namespaced("", "pods,services,configmaps"), Modes: []string{"all", "triage", "select"},
	}
}

func (RuntimeDependencyRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	services := map[string]struct{}{}
	for i := range snapshot.Services {
		services[snapshot.Services[i].Namespace+"/"+snapshot.Services[i].Name] = struct{}{}
	}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		pvcVolumes := map[string]string{}
		for _, volume := range pod.Spec.Volumes {
			if volume.PersistentVolumeClaim != nil {
				pvcVolumes[volume.Name] = volume.PersistentVolumeClaim.ClaimName
			}
		}
		for _, container := range pod.Spec.Containers {
			commandText := strings.Join(append(append([]string{}, container.Command...), container.Args...), " ")
			for _, env := range container.Env {
				if env.Value != "" {
					result = append(result, envServiceFindings(pod, container, env, services, snapshot.ScopeNamespace)...)
				}
				if env.ValueFrom != nil && env.ValueFrom.ConfigMapKeyRef != nil {
					if !snapshot.AvailableOrUntracked("configmaps") {
						continue
					}
					selector := env.ValueFrom.ConfigMapKeyRef
					cm := selector.Name
					configMap, exists := snapshot.ConfigMap(pod.Namespace, cm)
					if !exists {
						// DependencyRule reports the missing object. A ConfigMap that is
						// not present cannot have a stale value in the running Pod.
						continue
					}
					if _, exists := configMap.Data[selector.Key]; !exists {
						// The missing-key diagnostic owns this state as well.
						continue
					}
					if !configMapRolloutTracked(pod, cm, env.ValueFrom.ConfigMapKeyRef.Key, snapshot) {
						result = append(result, model.NewFinding(model.Candidate, "K8S.CONFIGMAP.ENV_RESTART_REQUIRED", "ConfigMap", ref("ConfigMap", pod.Namespace, cm), "EnvironmentNotReloaded", pod.Name+"/"+container.Name+"/"+env.Name,
							fmt.Sprintf("Pod %s の環境変数 %q は ConfigMap %s から起動時に読み込まれます。ConfigMapを更新しても実行中コンテナの環境変数は変わらず、rollout用annotationも確認できないため、反映にはPodの再作成が必要です", shortRef(pod.Namespace, pod.Name), env.Name, shortRef(pod.Namespace, cm)), 45))
					}
				}
			}
			if finding, ok := sequentialAddressTimeoutFinding(pod, &container, commandText); ok {
				result = append(result, finding)
			}
			if pod.Spec.SecurityContext == nil || pod.Spec.SecurityContext.FSGroup == nil {
				for _, mount := range container.VolumeMounts {
					claim, ok := pvcVolumes[mount.Name]
					if !ok || mount.ReadOnly {
						continue
					}
					if containerRunsNonRoot(pod, &container) {
						result = append(result, model.NewFinding(model.Candidate, "K8S.PVC.NON_ROOT_WITHOUT_FSGROUP", "ストレージ", ref("Pod", pod.Namespace, pod.Name), "PVCWritePermissionRisk", container.Name+"/"+mount.Name,
							fmt.Sprintf("Pod %s の非rootコンテナ %q はPVC %qを読み書き可能でマウントしていますが、Podの securityContext.fsGroup がありません。ボリュームの所有権によっては書き込みが permission denied になります", shortRef(pod.Namespace, pod.Name), container.Name, claim), 65))
					}
				}
			}
			for _, volume := range pod.Spec.Volumes {
				if volume.Secret == nil {
					continue
				}
				expectedPath := "/etc/" + volume.Name
				if !strings.Contains(commandText, expectedPath+"/") {
					continue
				}
				correctPathMounted := false
				for _, mount := range container.VolumeMounts {
					if mount.Name == volume.Name && strings.TrimSuffix(mount.MountPath, "/") == expectedPath {
						correctPathMounted = true
						break
					}
				}
				if correctPathMounted {
					continue
				}
				for _, mount := range container.VolumeMounts {
					if mount.Name == volume.Name && strings.TrimSuffix(mount.MountPath, "/") != expectedPath {
						result = append(result, model.NewFinding(model.Warning, "K8S.SECRET.MOUNT_PATH_MISMATCH", "関連リソース", ref("Pod", pod.Namespace, pod.Name), "SecretMountPathMismatch", container.Name+"/"+volume.Name,
							fmt.Sprintf("Pod %s のコンテナ %q はSecretボリューム %q を %q にマウントしていますが、command/argsは %q 配下を参照しています。参照パスとmountPathが一致していません", shortRef(pod.Namespace, pod.Name), container.Name, volume.Name, mount.MountPath, expectedPath), 90))
					}
				}
			}
		}
	}
	return result
}

func configMapRolloutTracked(pod *corev1.Pod, name, key string, snapshot *kube.Snapshot) bool {
	configMap, ok := snapshot.ConfigMap(pod.Namespace, name)
	if !ok {
		return false
	}
	wanted := configMap.Data[key]
	for annotationKey, value := range pod.Annotations {
		lower := strings.ToLower(annotationKey)
		tracksConfig := strings.Contains(lower, "checksum") && (strings.Contains(lower, "config") || strings.Contains(lower, strings.ToLower(name)))
		if tracksConfig || wanted != "" && value == wanted {
			return true
		}
	}
	return false
}

func envServiceFindings(pod *corev1.Pod, container corev1.Container, env corev1.EnvVar, services map[string]struct{}, scopeNamespace string) []model.Finding {
	value := strings.TrimSpace(env.Value)
	host := environmentHost(value)
	trimmed := strings.TrimSuffix(strings.ToLower(host), ".")
	parts := strings.Split(trimmed, ".")
	result := []model.Finding{}
	if len(parts) == 5 && parts[2] == "svc" && parts[3] == "cluster" && parts[4] == "local" {
		name, namespace := parts[0], parts[1]
		_, serviceExists := services[namespace+"/"+name]
		canProveAbsence := scopeNamespace == "" || scopeNamespace == namespace
		if !serviceExists && canProveAbsence {
			result = append(result, model.NewFinding(model.Warning, "K8S.DEPENDENCY.ENV_SERVICE_NOT_FOUND", "関連リソース", ref("Pod", pod.Namespace, pod.Name), "EnvironmentServiceNotFound", container.Name+"/"+env.Name,
				fmt.Sprintf("Pod %s の環境変数 %q がService形式のDNS名 %qを指定していますが、Service %s/%s は存在しません", shortRef(pod.Namespace, pod.Name), env.Name, host, namespace, name), 90))
		}
		ndots, ndotsKnown := podNDots(pod)
		if serviceExists && !strings.HasSuffix(host, ".") && ndotsKnown && ndots >= 5 {
			result = append(result, model.NewFinding(model.Candidate, "K8S.DNS.FQDN_SEARCH_EXPANSION", "DNS", ref("Pod", pod.Namespace, pod.Name), "FQDNWithoutTrailingDot", container.Name+"/"+env.Name,
				fmt.Sprintf("Pod %s の環境変数 %q は末尾ドットなしのクラスタFQDN %q で、resolverは ndots:%d です。検索ドメイン展開による余分なDNS問い合わせを避けるには末尾ドット付きFQDNを検討してください", shortRef(pod.Namespace, pod.Name), env.Name, host, ndots), 65))
		}
	}
	if len(parts) == 1 && parts[0] != "" && parts[0] != "localhost" {
		if _, ok := services[pod.Namespace+"/"+parts[0]]; ok && len(pod.Spec.InitContainers) == 0 {
			result = append(result, model.NewFinding(model.Candidate, "K8S.DEPENDENCY.STARTUP_NOT_GATED", "関連リソース", ref("Pod", pod.Namespace, pod.Name), "StartupDependencyNotGated", container.Name+"/"+env.Name,
				fmt.Sprintf("Pod %s の環境変数 %q はService %s/%sを参照しますが、initContainerがありません。アプリが依存先を起動時に一度だけ確認する場合、依存先より先に起動すると失敗状態を保持する可能性があります", shortRef(pod.Namespace, pod.Name), env.Name, pod.Namespace, parts[0]), 45))
		}
	}
	return result
}

func environmentHost(value string) string {
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	return value
}

// sequentialAddressTimeoutFinding mirrors the failure mode exercised by the
// connectivity checker: getaddrinfo results are tried one by one, IPv6 is
// explicitly preferred, and each failed address consumes the configured
// timeout before IPv4 fallback. A timeout value alone is not an error.
func sequentialAddressTimeoutFinding(pod *corev1.Pod, container *corev1.Container, commandText string) (model.Finding, bool) {
	requiredCode := []string{"getaddrinfo", "AF_INET6", "settimeout", ".connect("}
	for _, token := range requiredCode {
		if !strings.Contains(commandText, token) {
			return model.Finding{}, false
		}
	}
	for _, env := range container.Env {
		if env.Name != "CONNECT_TIMEOUT_SECONDS" {
			continue
		}
		seconds, err := strconv.ParseFloat(env.Value, 64)
		if err != nil || seconds < 0.5 {
			return model.Finding{}, false
		}
		return model.NewFinding(model.Candidate, "K8S.CONFIG.CONNECT_TIMEOUT_HIGH", "構成リスク", ref("Pod", pod.Namespace, pod.Name), "SequentialAddressFallbackDelay", container.Name+"/"+env.Name,
			fmt.Sprintf("Pod %s のコンテナ %q はIPv6を優先してgetaddrinfoの結果へ順番に接続し、各アドレスに %.3g秒のタイムアウトを適用します。先頭アドレスが応答しない場合、IPv4へ切り替わるまでこの時間だけ接続テストが遅延します", shortRef(pod.Namespace, pod.Name), container.Name, seconds), 85), true
	}
	return model.Finding{}, false
}

func podNDots(pod *corev1.Pod) (int, bool) {
	if pod.Spec.DNSConfig != nil {
		for _, option := range pod.Spec.DNSConfig.Options {
			if option.Name == "ndots" && option.Value != nil {
				if value, err := strconv.Atoi(*option.Value); err == nil {
					return value, true
				}
			}
		}
	}
	// Kubernetes generates ndots:5 for ClusterFirst policies. Default inherits
	// the node resolver and None is fully user-controlled, so neither can be
	// asserted from the Pod manifest when no explicit option is present.
	switch pod.Spec.DNSPolicy {
	case "", corev1.DNSClusterFirst, corev1.DNSClusterFirstWithHostNet:
		return 5, true
	default:
		return 0, false
	}
}

func containerRunsNonRoot(pod *corev1.Pod, container *corev1.Container) bool {
	if container.SecurityContext != nil {
		if container.SecurityContext.RunAsNonRoot != nil && *container.SecurityContext.RunAsNonRoot {
			return true
		}
		if container.SecurityContext.RunAsUser != nil {
			return *container.SecurityContext.RunAsUser != 0
		}
	}
	if pod.Spec.SecurityContext != nil {
		if pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot {
			return true
		}
		if pod.Spec.SecurityContext.RunAsUser != nil {
			return *pod.Spec.SecurityContext.RunAsUser != 0
		}
	}
	return false
}
