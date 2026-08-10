package rules

import (
	"context"
	"fmt"
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
	return Metadata{ID: "persistent-volumes", Section: "PV", Description: "PersistentVolume phase", Required: []string{"pvs"}, Permissions: cluster("", "persistentvolumes"), Modes: []string{"all", "triage"}}
}

func (PersistentVolumeRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.PersistentVolumes {
		volume := &snapshot.PersistentVolumes[i]
		resource := ref("PersistentVolume", "", volume.Name)
		switch volume.Status.Phase {
		case corev1.VolumeFailed:
			result = append(result, model.NewFinding(model.Issue, "K8S.PV.FAILED", "PV", resource, string(volume.Status.Phase), "phase", fmt.Sprintf("PersistentVolume %s: phase=Failed (%s)", volume.Name, volume.Status.Message), 98))
		case corev1.VolumeReleased:
			result = append(result, model.NewFinding(model.Warning, "K8S.PV.RELEASED", "PV", resource, string(volume.Status.Phase), "phase", fmt.Sprintf("PersistentVolume %s: phase=Released (reclaim待ちまたは手動回収が必要)", volume.Name), 75))
		case corev1.VolumePending:
			if elapsedSince(snapshot, volume.CreationTimestamp.Time) >= 10*time.Minute {
				result = append(result, model.NewFinding(model.Candidate, "K8S.PV.PENDING", "PV", resource, string(volume.Status.Phase), "phase", fmt.Sprintf("PersistentVolume %s: Pendingが10分以上継続しています", volume.Name), 45))
			}
		}
	}
	return result
}

type CronJobRule struct{}

func (CronJobRule) Metadata() Metadata {
	return Metadata{ID: "cronjobs", Section: "Job", Description: "CronJob suspend・schedule状態", Required: []string{"cronjobs"}, Permissions: namespaced("batch", "cronjobs"), Modes: []string{"all", "triage"}}
}

func (CronJobRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.CronJobs {
		cronJob := &snapshot.CronJobs[i]
		if cronJob.Spec.Suspend != nil && *cronJob.Spec.Suspend {
			result = append(result, model.NewFinding(model.Candidate, "K8S.CRONJOB.SUSPENDED", "Job", ref("CronJob", cronJob.Namespace, cronJob.Name), "Suspended", "suspend", fmt.Sprintf("CronJob %s: suspend=trueです", shortRef(cronJob.Namespace, cronJob.Name)), 45))
		}
	}
	return result
}

type NetworkPolicyRule struct{}

func (NetworkPolicyRule) Metadata() Metadata {
	permissions := namespaced("networking.k8s.io", "networkpolicies")
	permissions = append(permissions, namespaced("", "pods")...)
	return Metadata{ID: "network-policies", Section: "NetworkPolicy", Description: "NetworkPolicyのPod selector適用状況", Required: []string{"networkpolicies", "pods"}, Permissions: permissions, Modes: []string{"all", "triage"}}
}

type LimitRangeRule struct{}

func (LimitRangeRule) Metadata() Metadata {
	return Metadata{ID: "limit-ranges", Section: "LimitRange", Description: "既存PodとLimitRangeのmin/max整合", Required: []string{"limitranges", "pods"}, Permissions: namespaced("", "limitranges,pods"), Modes: []string{"all", "triage"}}
}

func (LimitRangeRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for rangeIndex := range snapshot.LimitRanges {
		limitRange := &snapshot.LimitRanges[rangeIndex]
		for _, item := range limitRange.Spec.Limits {
			if item.Type != corev1.LimitTypeContainer {
				continue
			}
			for podIndex := range snapshot.Pods {
				pod := &snapshot.Pods[podIndex]
				if pod.Namespace != limitRange.Namespace {
					continue
				}
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
	return model.NewFinding(model.Candidate, "K8S.LIMIT_RANGE.EXISTING_POD_MISMATCH", "LimitRange", ref("Pod", pod.Namespace, pod.Name), "ExistingPodMismatch", container+"/"+string(resourceName)+"/"+boundaryLabel,
		fmt.Sprintf("Pod %s / container %s: %s %s=%s はLimitRange %sの%s=%sと不一致です (Policy変更前に作成された可能性)", shortRef(pod.Namespace, pod.Name), container, resourceName, actualLabel, actual, limitRangeName, boundaryLabel, boundary), 45)
}

func (NetworkPolicyRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.NetworkPolicies {
		policy := &snapshot.NetworkPolicies[i]
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			result = append(result, model.NewFinding(model.Unavailable, "K8S.NETWORK_POLICY.SELECTOR_UNAVAILABLE", "NetworkPolicy", ref("NetworkPolicy", policy.Namespace, policy.Name), "SelectorParseFailed", "selector", fmt.Sprintf("NetworkPolicy %s: selectorを解析できません", shortRef(policy.Namespace, policy.Name)), 100))
			continue
		}
		matched := 0
		for podIndex := range snapshot.Pods {
			pod := &snapshot.Pods[podIndex]
			if pod.Namespace == policy.Namespace && selector.Matches(labels.Set(pod.Labels)) {
				matched++
			}
		}
		if matched == 0 && elapsedSince(snapshot, policy.CreationTimestamp.Time) >= 5*time.Minute {
			result = append(result, model.NewFinding(model.Candidate, "K8S.NETWORK_POLICY.SELECTOR_NO_MATCH", "NetworkPolicy", ref("NetworkPolicy", policy.Namespace, policy.Name), "SelectorNoMatch", "selector", fmt.Sprintf("NetworkPolicy %s: podSelectorに一致するPodが0件です", shortRef(policy.Namespace, policy.Name)), 40))
		}
	}
	return result
}
