package rules

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type PersistentVolumeRule struct{}

func (PersistentVolumeRule) Metadata() Metadata {
	return Metadata{ID: "persistent-volumes", Section: "PV", Description: "PersistentVolumeの状態", Required: []string{"pvs"}, Permissions: cluster("", "persistentvolumes"), Modes: []string{"all", "triage", "select"}}
}

func (PersistentVolumeRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.PersistentVolumes {
		volume := &snapshot.PersistentVolumes[i]
		resource := ref("PersistentVolume", "", volume.Name)
		switch volume.Status.Phase {
		case corev1.VolumeFailed:
			message := fmt.Sprintf("PersistentVolume %s の状態（phase）は Failed です", volume.Name)
			if volume.Status.Message != "" {
				message += "。詳細: " + volume.Status.Message
			}
			result = append(result, model.NewFinding(model.Issue, "K8S.PV.FAILED", "PV", resource, string(volume.Status.Phase), "phase", message, 98))
		case corev1.VolumeReleased:
			result = append(result, model.NewFinding(model.Warning, "K8S.PV.RELEASED", "PV", resource, string(volume.Status.Phase), "phase", fmt.Sprintf("PersistentVolume %s の状態（phase）は Released です。再利用ポリシーに応じた回収処理を確認してください", volume.Name), 75))
		case corev1.VolumePending:
			if elapsedSince(snapshot, volume.CreationTimestamp.Time) >= 10*time.Minute {
				result = append(result, model.NewFinding(model.Candidate, "K8S.PV.PENDING", "PV", resource, string(volume.Status.Phase), "phase", fmt.Sprintf("PersistentVolume %s の Pending 状態が10分以上続いています", volume.Name), 45))
			}
		}
	}
	return result
}

type CronJobRule struct{}

var shellOutputRedirect = regexp.MustCompile(`(?:^|[;&|]\s*)[^;&|]*?>+\s*([^\s;&|]+)`)

func (CronJobRule) Metadata() Metadata {
	return Metadata{ID: "cronjobs", Section: "Job", Description: "CronJobの一時停止状態とスケジュール", Required: []string{"cronjobs"}, Permissions: namespaced("batch", "cronjobs"), Modes: []string{"all", "triage"}}
}

func (CronJobRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.CronJobs {
		cronJob := &snapshot.CronJobs[i]
		if cronJob.Spec.Suspend != nil && *cronJob.Spec.Suspend {
			result = append(result, model.NewFinding(model.Candidate, "K8S.CRONJOB.SUSPENDED", "Job", ref("CronJob", cronJob.Namespace, cronJob.Name), "Suspended", "suspend", fmt.Sprintf("CronJob %s は一時停止されています（spec.suspend: true）", shortRef(cronJob.Namespace, cronJob.Name)), 45))
		}
		for _, container := range cronJob.Spec.JobTemplate.Spec.Template.Spec.Containers {
			commandText := strings.Join(append(append([]string{}, container.Command...), container.Args...), " ")
			redirects := shellOutputRedirect.FindAllStringSubmatch(commandText, -1)
			if len(redirects) == 0 {
				// A process may use the mounted volume through its defaults or
				// environment. Only an explicit shell redirect outside the mount
				// is strong enough evidence for this diagnostic.
				continue
			}
			for _, mount := range container.VolumeMounts {
				if mount.ReadOnly || mount.MountPath == "" {
					continue
				}
				writesToMount := false
				for _, match := range redirects {
					if len(match) > 1 && strings.HasPrefix(match[1], strings.TrimSuffix(mount.MountPath, "/")+"/") {
						writesToMount = true
					}
				}
				if writesToMount {
					continue
				}
				result = append(result, model.NewFinding(model.Candidate, "K8S.CRONJOB.MOUNT_PATH_UNUSED", "Job", ref("CronJob", cronJob.Namespace, cronJob.Name), "MountedPathNotReferenced", container.Name+"/"+mount.Name,
					fmt.Sprintf("CronJob %s のコンテナ %q はボリュームを %q にマウントしていますが、command/argsの明示的な出力redirectはこの配下を使っていません。処理結果を一時ファイルシステムへ書き込んでいる可能性があります", shortRef(cronJob.Namespace, cronJob.Name), container.Name, mount.MountPath), 78))
			}
		}
	}
	return result
}

type NetworkPolicyRule struct{}

func (NetworkPolicyRule) Metadata() Metadata {
	permissions := namespaced("networking.k8s.io", "networkpolicies")
	permissions = append(permissions, namespaced("", "pods")...)
	return Metadata{ID: "network-policies", Section: "NetworkPolicy", Description: "NetworkPolicyのPod選択条件の適用状況", Required: []string{"networkpolicies", "pods"}, Permissions: permissions, Modes: []string{"all", "triage", "select"}}
}

type LimitRangeRule struct{}

func (LimitRangeRule) Metadata() Metadata {
	return Metadata{ID: "limit-ranges", Section: "LimitRange", Description: "既存PodとLimitRangeの最小値・最大値の整合性", Required: []string{"limitranges", "pods"}, Permissions: namespaced("", "limitranges,pods"), Modes: []string{"all", "triage", "select"}}
}

func (LimitRangeRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	// Look up only the pods in the LimitRange's own namespace instead of
	// rescanning every pod in the cluster for each LimitRange.
	podIndex := indexPodsByNamespace(snapshot.Pods)
	for rangeIndex := range snapshot.LimitRanges {
		limitRange := &snapshot.LimitRanges[rangeIndex]
		for _, item := range limitRange.Spec.Limits {
			if item.Type != corev1.LimitTypeContainer {
				continue
			}
			for _, pod := range podIndex[limitRange.Namespace] {
				containers := append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
				for _, container := range containers {
					for resourceName, minimum := range item.Min {
						request, exists := container.Resources.Requests[resourceName]
						if exists && request.Cmp(minimum) < 0 {
							result = append(result, limitRangeMismatch(limitRange.Name, pod, container.Name, resourceName, "request", request.String(), "min", minimum.String()))
						}
					}
					for resourceName, maximum := range item.Max {
						limit, exists := container.Resources.Limits[resourceName]
						if exists && limit.Cmp(maximum) > 0 {
							result = append(result, limitRangeMismatch(limitRange.Name, pod, container.Name, resourceName, "limit", limit.String(), "max", maximum.String()))
						}
					}
				}
			}
		}
	}
	return result
}

func limitRangeMismatch(limitRangeName string, pod *corev1.Pod, container string, resourceName corev1.ResourceName, actualLabel, actual, boundaryLabel, boundary string) model.Finding {
	actualText := map[string]string{"request": "要求量（request）", "limit": "上限値（limit）"}[actualLabel]
	boundaryText := map[string]string{"min": "最小値（min）", "max": "最大値（max）"}[boundaryLabel]
	return model.NewFinding(model.Candidate, "K8S.LIMIT_RANGE.EXISTING_POD_MISMATCH", "LimitRange", ref("Pod", pod.Namespace, pod.Name), "ExistingPodMismatch", container+"/"+string(resourceName)+"/"+boundaryLabel,
		fmt.Sprintf("Pod %s のコンテナ %q では、リソース %q の%sが %s です。LimitRange %q で定められた%s %s を満たしていないため、LimitRangeの変更前に作成されたPodか確認してください", shortRef(pod.Namespace, pod.Name), container, resourceName, actualText, actual, limitRangeName, boundaryText, boundary), 45)
}

func (NetworkPolicyRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	podIndex := indexPodsByNamespace(snapshot.Pods)
	for i := range snapshot.NetworkPolicies {
		policy := &snapshot.NetworkPolicies[i]
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			result = append(result, model.NewFinding(model.Unavailable, "K8S.NETWORK_POLICY.SELECTOR_UNAVAILABLE", "NetworkPolicy", ref("NetworkPolicy", policy.Namespace, policy.Name), "SelectorParseFailed", "selector", fmt.Sprintf("NetworkPolicy %s のPod選択条件（podSelector）を解析できません", shortRef(policy.Namespace, policy.Name)), 100))
			continue
		}
		matched := 0
		for _, pod := range podIndex[policy.Namespace] {
			if selector.Matches(labels.Set(pod.Labels)) {
				matched++
			}
		}
		if matched == 0 && elapsedSince(snapshot, policy.CreationTimestamp.Time) >= 5*time.Minute {
			result = append(result, model.NewFinding(model.Candidate, "K8S.NETWORK_POLICY.SELECTOR_NO_MATCH", "NetworkPolicy", ref("NetworkPolicy", policy.Namespace, policy.Name), "SelectorNoMatch", "selector", fmt.Sprintf("NetworkPolicy %s のPod選択条件（podSelector）に一致するPodが見つかりません", shortRef(policy.Namespace, policy.Name)), 40))
		}
		if matched == 0 {
			// Until the policy selects a destination Pod, an ingress peer has no
			// effective traffic path to diagnose and reporting both selectors is
			// misleading.
			continue
		}
		for ruleIndex, ingress := range policy.Spec.Ingress {
			for peerIndex, peer := range ingress.From {
				if peer.PodSelector == nil || peer.NamespaceSelector != nil {
					continue
				}
				peerSelector, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
				if err != nil {
					continue
				}
				peerMatches := 0
				for _, pod := range podIndex[policy.Namespace] {
					if peerSelector.Matches(labels.Set(pod.Labels)) {
						peerMatches++
					}
				}
				if peerMatches == 0 {
					stable := fmt.Sprintf("ingress/%d/from/%d", ruleIndex, peerIndex)
					result = append(result, model.NewFinding(model.Candidate, "K8S.NETWORK_POLICY.PEER_SELECTOR_NO_MATCH", "NetworkPolicy", ref("NetworkPolicy", policy.Namespace, policy.Name), "PeerSelectorNoMatch", stable,
						fmt.Sprintf("NetworkPolicy %s の ingress.from[%d] にあるPod選択条件に一致する送信元Podが、同じnamespaceに見つかりません。この許可ルールは通信を一件も許可しない可能性があります", shortRef(policy.Namespace, policy.Name), peerIndex), 70))
				}
			}
		}
	}
	return result
}
