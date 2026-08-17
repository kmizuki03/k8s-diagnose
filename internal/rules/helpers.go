package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func reasonSuffix(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return ""
	}
	return fmt.Sprintf("（Kubernetesが報告した理由: %s）", reason)
}

func conditionStateMessage(kind, reference, conditionType, status, reason string) string {
	return fmt.Sprintf("%s %s の状態条件（condition） %q は %s です%s", kind, reference, conditionType, status, reasonSuffix(reason))
}

func readyCountMessage(kind, reference string, ready, desired int32) string {
	return fmt.Sprintf("%s %s のReady状態のレプリカ数は %d/%d です", kind, reference, ready, desired)
}

func objectStringField(values map[string]any, key string) string {
	if values == nil || values[key] == nil {
		return ""
	}
	return fmt.Sprint(values[key])
}

func ref(kind, namespace, name string) string {
	if namespace == "" {
		return kind + "/" + name
	}
	return kind + "/" + namespace + "/" + name
}

func shortRef(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

func condition(conditions []corev1.PodCondition, kind corev1.PodConditionType) *corev1.PodCondition {
	for index := range conditions {
		if conditions[index].Type == kind {
			return &conditions[index]
		}
	}
	return nil
}

// workloadContainerStatuses excludes ephemeral containers. Ephemeral
// containers are debugging aids and their termination does not determine Pod
// readiness or phase.
func workloadContainerStatuses(pod *corev1.Pod) []corev1.ContainerStatus {
	values := append([]corev1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	values = append(values, pod.Status.ContainerStatuses...)
	return values
}

var confirmedWaiting = map[string]bool{"CrashLoopBackOff": true, "ImagePullBackOff": true, "ErrImagePull": true, "CreateContainerConfigError": true, "CreateContainerError": true, "RunContainerError": true, "InvalidImageName": true}

func ownerRef(meta metav1.ObjectMeta) *metav1.OwnerReference {
	for index := range meta.OwnerReferences {
		if meta.OwnerReferences[index].Controller != nil && *meta.OwnerReferences[index].Controller {
			return &meta.OwnerReferences[index]
		}
	}
	if len(meta.OwnerReferences) > 0 {
		return &meta.OwnerReferences[0]
	}
	return nil
}

func podOwnedByJob(pod *corev1.Pod) bool {
	owner := ownerRef(pod.ObjectMeta)
	return owner != nil && owner.Kind == "Job"
}

// podsByNamespace groups pods once so selector matching does not rescan every
// pod in the cluster for every Service. Matching Services against Pods is the
// single most expensive thing the rule set does: it was measured quadratic
// (input x2 -> time x4), reaching 143ms for the Service rule alone at 12k pods.
type podsByNamespace map[string][]*corev1.Pod

func indexPodsByNamespace(pods []corev1.Pod) podsByNamespace {
	index := make(podsByNamespace)
	for i := range pods {
		pod := &pods[i]
		index[pod.Namespace] = append(index[pod.Namespace], pod)
	}
	return index
}

// selected returns the pods matching a Service's selector. The selector is
// built once per Service rather than once per (Service, Pod) pair, and only
// pods in the Service's own namespace are considered.
func (index podsByNamespace) selected(service *corev1.Service) []*corev1.Pod {
	result := []*corev1.Pod{}
	if len(service.Spec.Selector) == 0 {
		return result
	}
	candidates := index[service.Namespace]
	if len(candidates) == 0 {
		return result
	}
	selector := labels.SelectorFromSet(service.Spec.Selector)
	for _, pod := range candidates {
		if selector.Matches(labels.Set(pod.Labels)) {
			result = append(result, pod)
		}
	}
	return result
}

func selectedPods(service *corev1.Service, pods []corev1.Pod) []*corev1.Pod {
	return indexPodsByNamespace(pods).selected(service)
}

func serviceTargetPort(port corev1.ServicePort) intstr.IntOrString {
	if port.TargetPort.Type == intstr.String && port.TargetPort.StrVal == "" {
		return intstr.FromInt32(port.Port)
	}
	if port.TargetPort.Type == intstr.Int && port.TargetPort.IntVal == 0 {
		return intstr.FromInt32(port.Port)
	}
	return port.TargetPort
}

func containerPorts(pod *corev1.Pod) (map[string]map[int32]struct{}, map[string]map[string]struct{}) {
	numeric := map[string]map[int32]struct{}{}
	named := map[string]map[string]struct{}{}
	add := func(protocol corev1.Protocol, number int32, name string) {
		p := string(protocol)
		if p == "" {
			p = string(corev1.ProtocolTCP)
		}
		if numeric[p] == nil {
			numeric[p] = map[int32]struct{}{}
		}
		numeric[p][number] = struct{}{}
		if name != "" {
			if named[p] == nil {
				named[p] = map[string]struct{}{}
			}
			named[p][name] = struct{}{}
		}
	}
	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			add(port.Protocol, port.ContainerPort, port.Name)
		}
	}
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			for _, port := range container.Ports {
				add(port.Protocol, port.ContainerPort, port.Name)
			}
		}
	}
	return numeric, named
}

func eventTime(event *corev1.Event) time.Time {
	latest := event.CreationTimestamp.Time
	for _, candidate := range []time.Time{event.FirstTimestamp.Time, event.LastTimestamp.Time, event.EventTime.Time} {
		if candidate.After(latest) {
			latest = candidate
		}
	}
	if event.Series != nil && event.Series.LastObservedTime.Time.After(latest) {
		latest = event.Series.LastObservedTime.Time
	}
	return latest
}

func int32Value(value *int32, fallback int32) int32 {
	if value == nil {
		return fallback
	}
	return *value
}

func statusGenerationCurrent(generation, observed int64) bool {
	return generation == 0 || observed >= generation
}

func statusGenerationPointerCurrent(generation int64, observed *int64) bool {
	return generation == 0 || observed != nil && *observed >= generation
}
func boolValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
func messageForStatus(status corev1.ContainerStatus) string {
	if status.State.Waiting != nil {
		return status.State.Waiting.Message
	}
	if status.State.Terminated != nil {
		return status.State.Terminated.Message
	}
	return ""
}
func statusReason(status corev1.ContainerStatus) string {
	if status.State.Waiting != nil {
		return status.State.Waiting.Reason
	}
	if status.State.Terminated != nil {
		if status.State.Terminated.Reason == "Completed" && status.State.Terminated.ExitCode == 0 {
			return ""
		}
		return status.State.Terminated.Reason
	}
	return ""
}

// evaluationTime keeps every rule that compares Kubernetes timestamps on the
// same clock. API Server Date is preferred because an operator workstation can
// be skewed from the cluster; local time is only a fallback for servers that do
// not return Date.
func evaluationTime(snapshot *kube.Snapshot) time.Time {
	if snapshot != nil && !snapshot.ServerTime.IsZero() {
		return snapshot.ServerTime
	}
	return time.Now()
}

func elapsedSince(snapshot *kube.Snapshot, timestamp time.Time) time.Duration {
	if timestamp.IsZero() {
		return 0
	}
	elapsed := evaluationTime(snapshot).Sub(timestamp)
	if elapsed < 0 {
		return 0
	}
	return elapsed
}
