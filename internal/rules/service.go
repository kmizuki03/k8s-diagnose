package rules

import (
	"context"
	"fmt"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
	intstrutil "k8s.io/apimachinery/pkg/util/intstr"
)

type ServiceRule struct{}

func (ServiceRule) Metadata() Metadata {
	permissions := namespaced("", "services,pods,endpoints")
	permissions = append(permissions, namespaced("discovery.k8s.io", "endpointslices")...)
	return Metadata{
		ID: "services", Section: "Service", Description: "Service selector・Endpoint・targetPort",
		Required:    []string{"services"},
		Optional:    []string{"pods", "endpoint_slices", "endpoints"},
		Permissions: permissions, Modes: []string{"all", "triage", "select"},
	}
}

func (ServiceRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	for i := range snapshot.Services {
		service := &snapshot.Services[i]
		if service.Spec.Type == corev1.ServiceTypeExternalName || len(service.Spec.Selector) == 0 {
			continue
		}
		resource := ref("Service", service.Namespace, service.Name)
		pods := selectedPods(service, snapshot.Pods)
		if snapshot.AvailableOrUntracked("pods") && len(pods) == 0 {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.SERVICE.SELECTOR_NO_MATCH", "Service", resource, "SelectorNoMatch", "selector-no-match",
				fmt.Sprintf("Service %s: selectorに一致するPodが0件です", shortRef(service.Namespace, service.Name)), 75,
			))
		}
		ready, fallback := serviceEndpointCounts(service, snapshot)
		endpointDataAvailable := snapshot.AvailableOrUntracked("endpoint_slices") || snapshot.AvailableOrUntracked("endpoints")
		if snapshot.AvailableOrUntracked("pods") && endpointDataAvailable && len(pods) > 0 && ready == 0 && fallback == 0 {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.SERVICE.NO_READY_ENDPOINT", "Service", resource, "NoReadyEndpoint", "ready-endpoint-zero",
				fmt.Sprintf("Service %s: Ready Endpointが0件です", shortRef(service.Namespace, service.Name)), 85,
			))
		} else if snapshot.AvailableOrUntracked("pods") && endpointDataAvailable && len(pods) > 0 && ready == 0 && fallback > 0 {
			result = append(result, model.NewFinding(
				model.Warning, "K8S.SERVICE.TERMINATING_ENDPOINTS_ONLY", "Service", resource, "TerminatingEndpointsOnly", "terminating-serving-endpoints",
				fmt.Sprintf("Service %s: 通常のReady Endpointがなく、終了中かつservingのEndpoint %d件だけがfallback候補です", shortRef(service.Namespace, service.Name), fallback), 88,
				model.Evidence{Kind: "endpoint", Key: "terminatingServing", Value: fmt.Sprint(fallback)},
			))
		}
		for _, port := range service.Spec.Ports {
			if !snapshot.AvailableOrUntracked("pods") {
				break
			}
			target := serviceTargetPort(port)
			if target.Type != intstrutil.String || target.StrVal == "" {
				continue // numeric targetPort need not be declared as containerPort
			}
			resolved := false
			for _, pod := range pods {
				_, named := containerPorts(pod)
				protocol := string(port.Protocol)
				if protocol == "" {
					protocol = string(corev1.ProtocolTCP)
				}
				if _, ok := named[protocol][target.StrVal]; ok {
					resolved = true
					break
				}
			}
			if !resolved && snapshot.AvailableOrUntracked("endpoint_slices") {
				resolved = endpointSliceResolvesPort(service, port, snapshot)
			}
			if !resolved && len(pods) > 0 {
				result = append(result, model.NewFinding(
					model.Issue, "K8S.SERVICE.TARGET_PORT_UNRESOLVED", "Service", resource, "TargetPortUnresolved", port.Name+"/"+target.StrVal,
					fmt.Sprintf("Service %s: targetPort %qをselector一致PodのcontainerPort名に解決できません", shortRef(service.Namespace, service.Name), target.StrVal), 98,
					model.Evidence{Kind: "service", Key: "targetPort", Value: target.StrVal},
				))
			}
		}
		if service.Spec.Type == corev1.ServiceTypeLoadBalancer && len(service.Status.LoadBalancer.Ingress) == 0 && elapsedSince(snapshot, service.CreationTimestamp.Time) >= 5*time.Minute {
			result = append(result, model.NewFinding(model.Candidate, "K8S.SERVICE.LOAD_BALANCER_PENDING", "Service", resource, "LoadBalancerPending", "load-balancer", fmt.Sprintf("Service %s: LoadBalancer ingressがまだ割り当てられていません", shortRef(service.Namespace, service.Name)), 50))
		}
	}
	return result
}

func endpointSliceResolvesPort(service *corev1.Service, servicePort corev1.ServicePort, snapshot *kube.Snapshot) bool {
	protocol := servicePort.Protocol
	if protocol == "" {
		protocol = corev1.ProtocolTCP
	}
	for i := range snapshot.EndpointSlices {
		slice := &snapshot.EndpointSlices[i]
		if slice.Namespace != service.Namespace || slice.Labels["kubernetes.io/service-name"] != service.Name {
			continue
		}
		for _, endpointPort := range slice.Ports {
			endpointProtocol := corev1.ProtocolTCP
			if endpointPort.Protocol != nil {
				endpointProtocol = *endpointPort.Protocol
			}
			if endpointPort.Port == nil || endpointProtocol != protocol {
				continue
			}
			if servicePort.Name != "" {
				if endpointPort.Name != nil && *endpointPort.Name == servicePort.Name {
					return true
				}
				continue
			}
			if len(service.Spec.Ports) == 1 && (endpointPort.Name == nil || *endpointPort.Name == "") {
				return true
			}
		}
	}
	return false
}

func serviceEndpointCounts(service *corev1.Service, snapshot *kube.Snapshot) (ready, fallback int) {
	if endpointSlicesAuthoritative(snapshot) {
		for i := range snapshot.EndpointSlices {
			slice := &snapshot.EndpointSlices[i]
			if slice.Namespace != service.Namespace || slice.Labels["kubernetes.io/service-name"] != service.Name {
				continue
			}
			for _, endpoint := range slice.Endpoints {
				// EndpointSlice condition defaults are part of the API contract:
				// ready=nil and serving=nil mean true, terminating=nil means false.
				isReady := endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready
				isServing := endpoint.Conditions.Serving == nil || *endpoint.Conditions.Serving
				isTerminating := endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating
				switch {
				case isReady:
					ready++
				case isServing && isTerminating:
					fallback++
				}
			}
		}
		return ready, fallback
	}
	if snapshot.AvailableOrUntracked("endpoints") {
		for i := range snapshot.Endpoints {
			endpoint := &snapshot.Endpoints[i]
			if endpoint.Namespace != service.Namespace || endpoint.Name != service.Name {
				continue
			}
			for _, subset := range endpoint.Subsets {
				ready += len(subset.Addresses)
			}
		}
	}
	return ready, fallback
}

// A successful EndpointSlice list is authoritative even when it returns zero
// items. Legacy Endpoints is used only when EndpointSlice acquisition itself
// was unavailable, or by hand-built snapshots that contain no EndpointSlices.
func endpointSlicesAuthoritative(snapshot *kube.Snapshot) bool {
	status, tracked := snapshot.Statuses["endpoint_slices"]
	if tracked {
		return status.Available
	}
	return len(snapshot.EndpointSlices) > 0
}
