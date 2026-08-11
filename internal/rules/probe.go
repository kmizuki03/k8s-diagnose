package rules

import (
	"context"
	"fmt"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// ProbeConfigRule reports probe settings that kubelet cannot resolve. Keeping
// this independent from live port-forward checks ensures invalid manifests are
// visible in non-interactive and CI modes too.
type ProbeConfigRule struct{}

func (ProbeConfigRule) Metadata() Metadata {
	return Metadata{
		ID: "probe-config", Section: "Probe", Description: "Probeの名前付きポート設定",
		Required: []string{"pods"}, Permissions: namespaced("", "pods"),
		Modes: []string{"all", "triage", "select"},
	}
}

func (ProbeConfigRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.Pods {
		pod := &snapshot.Pods[i]
		forEachPodProbe(pod, func(container corev1.Container, probeType string, probe *corev1.Probe) {
			var port intstr.IntOrString
			switch {
			case probe.HTTPGet != nil:
				port = probe.HTTPGet.Port
			case probe.TCPSocket != nil:
				port = probe.TCPSocket.Port
			default:
				return
			}
			if port.Type != intstr.String || namedProbePortExists(container, port.StrVal) {
				return
			}
			resource := probeResource(pod.Namespace, pod.Name, container.Name, probeType)
			result = append(result, model.NewFinding(
				model.Issue, "K8S.PROBE.PORT_UNRESOLVED", "Probe", resource, "NamedPortUnresolved",
				probePortStableKey(container.Name, probeType, port.StrVal),
				fmt.Sprintf("Pod %s のコンテナ %q に設定された %s のポート %q を解決できません。同じコンテナの ports[].name には、%q が定義されていません", shortRef(pod.Namespace, pod.Name), container.Name, probeType, port.StrVal, port.StrVal), 100,
				model.Evidence{Kind: "probe", Key: "portName", Value: fmt.Sprintf("%s.port: %q", probeType, port.StrVal)},
				model.Evidence{Kind: "container", Key: "ports[].name", Value: fmt.Sprintf("コンテナ %q の ports[].name に %q は定義されていません", container.Name, port.StrVal)},
			))
		})
	}
	return result
}

func forEachPodProbe(pod *corev1.Pod, visit func(corev1.Container, string, *corev1.Probe)) {
	visitContainer := func(container corev1.Container) {
		for _, value := range []struct {
			name  string
			probe *corev1.Probe
		}{
			{"readinessProbe", container.ReadinessProbe},
			{"livenessProbe", container.LivenessProbe},
			{"startupProbe", container.StartupProbe},
		} {
			if value.probe != nil {
				visit(container, value.name, value.probe)
			}
		}
	}
	for _, container := range pod.Spec.InitContainers {
		if container.RestartPolicy != nil && *container.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			visitContainer(container)
		}
	}
	for _, container := range pod.Spec.Containers {
		visitContainer(container)
	}
}

func namedProbePortExists(container corev1.Container, name string) bool {
	for _, port := range container.Ports {
		if port.Name == name && port.ContainerPort >= 1 && port.ContainerPort <= 65535 {
			return true
		}
	}
	return false
}

func probeResource(namespace, pod, container, probeType string) string {
	return fmt.Sprintf("Probe/%s/%s/%s/%s", namespace, pod, container, probeType)
}

func probePortStableKey(container, probeType, portName string) string {
	return container + "/" + probeType + "/port/" + portName
}
