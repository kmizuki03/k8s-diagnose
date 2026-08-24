//lint:file-ignore SA1019 EndpointSlice is primary; legacy Endpoints is retained only to scope the existing compatibility fallback.

package app

import (
	"net"
	"net/url"
	"strings"

	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
)

// scopeSnapshotToSelectedPod keeps the capacity data needed by the scheduler
// simulation, while limiting rules which iterate namespace resources to the
// selected Pod's dependency graph. Without this step, one selected Pod and all
// Services in the namespace make every unrelated Service appear to have a
// selector with zero matching Pods.
func scopeSnapshotToSelectedPod(snapshot *kube.Snapshot, pod *corev1.Pod) *kube.Snapshot {
	if snapshot == nil || pod == nil {
		return snapshot
	}
	scoped := *snapshot
	scoped.ScopeNamespace = pod.Namespace
	scoped.Pods = []corev1.Pod{*pod.DeepCopy()}

	podIPs := map[string]struct{}{}
	if pod.Status.PodIP != "" {
		podIPs[pod.Status.PodIP] = struct{}{}
	}
	for _, value := range pod.Status.PodIPs {
		if value.IP != "" {
			podIPs[value.IP] = struct{}{}
		}
	}

	serviceNames := map[string]struct{}{}
	for i := range snapshot.Services {
		service := &snapshot.Services[i]
		if serviceSelectsPod(service, pod) || selectedPodReferencesService(pod, service) {
			serviceNames[namespacedName(service.Namespace, service.Name)] = struct{}{}
		}
	}
	// If the selected Pod references an ExternalName Service, retain an
	// in-cluster target too. Otherwise ServiceRule would see the alias in the
	// narrowed snapshot but incorrectly conclude that its existing target was
	// absent.
	for i := range snapshot.Services {
		service := &snapshot.Services[i]
		if service.Spec.Type != corev1.ServiceTypeExternalName {
			continue
		}
		if _, selected := serviceNames[namespacedName(service.Namespace, service.Name)]; !selected {
			continue
		}
		if namespace, name, ok := inClusterServiceDNSName(service.Spec.ExternalName); ok {
			serviceNames[namespacedName(namespace, name)] = struct{}{}
		}
	}
	for i := range snapshot.EndpointSlices {
		slice := &snapshot.EndpointSlices[i]
		if endpointSliceTargetsPod(slice, pod, podIPs) {
			if name := slice.Labels[discoveryv1.LabelServiceName]; name != "" {
				serviceNames[namespacedName(slice.Namespace, name)] = struct{}{}
			}
		}
	}
	for i := range snapshot.Endpoints {
		endpoint := &snapshot.Endpoints[i]
		if endpointsTargetPod(endpoint, pod, podIPs) {
			serviceNames[namespacedName(endpoint.Namespace, endpoint.Name)] = struct{}{}
		}
	}

	scoped.Services = filterServices(snapshot.Services, serviceNames)
	scoped.EndpointSlices = filterEndpointSlices(snapshot.EndpointSlices, serviceNames, pod, podIPs)
	scoped.Endpoints = filterEndpoints(snapshot.Endpoints, serviceNames, pod, podIPs)
	scoped.Ingresses = filterIngresses(snapshot.Ingresses, serviceNames)

	configMapNames, secretNames := selectedPodObjectReferences(pod)
	for _, ingress := range scoped.Ingresses {
		for _, tls := range ingress.Spec.TLS {
			if tls.SecretName != "" {
				secretNames[tls.SecretName] = struct{}{}
			}
		}
	}
	scoped.ConfigMaps = nil
	for _, value := range snapshot.ConfigMaps {
		if value.Namespace == pod.Namespace {
			if _, exists := configMapNames[value.Name]; exists {
				scoped.ConfigMaps = append(scoped.ConfigMaps, value)
			}
		}
	}
	scoped.Secrets = nil
	for _, value := range snapshot.Secrets {
		if value.Namespace == pod.Namespace {
			if _, exists := secretNames[value.Name]; exists {
				scoped.Secrets = append(scoped.Secrets, value)
			}
		}
	}
	serviceAccountName := pod.Spec.ServiceAccountName
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}
	scoped.ServiceAccounts = nil
	for _, value := range snapshot.ServiceAccounts {
		if value.Namespace == pod.Namespace && value.Name == serviceAccountName {
			scoped.ServiceAccounts = append(scoped.ServiceAccounts, value)
		}
	}
	scoped.NetworkPolicies = filterNetworkPolicies(snapshot.NetworkPolicies, pod)
	scoped.PodMetrics = filterPodMetrics(snapshot.PodMetrics, pod)

	pvcNames := selectedPodPVCNames(pod)
	scoped.PersistentVolumeClaims = nil
	volumeNames := map[string]struct{}{}
	for i := range snapshot.PersistentVolumeClaims {
		pvc := snapshot.PersistentVolumeClaims[i]
		if pvc.Namespace != pod.Namespace {
			continue
		}
		if _, exists := pvcNames[pvc.Name]; !exists {
			continue
		}
		scoped.PersistentVolumeClaims = append(scoped.PersistentVolumeClaims, pvc)
		if pvc.Spec.VolumeName != "" {
			volumeNames[pvc.Spec.VolumeName] = struct{}{}
		}
	}
	scoped.PersistentVolumes = nil
	for i := range snapshot.PersistentVolumes {
		pv := snapshot.PersistentVolumes[i]
		_, named := volumeNames[pv.Name]
		claimed := pv.Spec.ClaimRef != nil && pv.Spec.ClaimRef.Namespace == pod.Namespace
		if claimed {
			_, claimed = pvcNames[pv.Spec.ClaimRef.Name]
		}
		if named || claimed {
			scoped.PersistentVolumes = append(scoped.PersistentVolumes, pv)
		}
	}

	scoped.Events = nil
	for i := range snapshot.Events {
		event := snapshot.Events[i]
		if objectReferenceMatches(&event.InvolvedObject, pod, event.Namespace) {
			scoped.Events = append(scoped.Events, event)
		}
	}

	// The shallow copy above inherited the source snapshot's cached name index,
	// which still describes the unfiltered collections. Drop it now that every
	// replacement is done, so the next lookup rebuilds it from the narrowed
	// collections. This must stay the last statement: resetting earlier would
	// leave a window in which any lookup added to this function would cache a
	// half-filtered index, and no existing test would fail.
	scoped.ResetIndex()
	return &scoped
}

func namespacedName(namespace, name string) string { return namespace + "/" + name }

func serviceSelectsPod(service *corev1.Service, pod *corev1.Pod) bool {
	if service.Namespace != pod.Namespace || len(service.Spec.Selector) == 0 {
		return false
	}
	for key, expected := range service.Spec.Selector {
		if pod.Labels[key] != expected {
			return false
		}
	}
	return true
}

func selectedPodReferencesService(pod *corev1.Pod, service *corev1.Service) bool {
	if service.Namespace != pod.Namespace {
		return false
	}
	hosts := map[string]struct{}{
		service.Name:                                                   {},
		service.Name + "." + service.Namespace:                         {},
		service.Name + "." + service.Namespace + ".svc":                {},
		service.Name + "." + service.Namespace + ".svc.cluster.local":  {},
		service.Name + "." + service.Namespace + ".svc.cluster.local.": {},
	}
	for _, container := range append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...) {
		for _, env := range container.Env {
			value := strings.TrimSpace(env.Value)
			host := value
			if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
				host = parsed.Hostname()
			} else if parsedHost, _, err := net.SplitHostPort(value); err == nil {
				host = strings.Trim(parsedHost, "[]")
			}
			if _, ok := hosts[strings.ToLower(host)]; ok {
				return true
			}
		}
		commandText := strings.ToLower(strings.Join(append(append([]string{}, container.Command...), container.Args...), " "))
		for host := range hosts {
			for _, scheme := range []string{"http://", "https://"} {
				if strings.Contains(commandText, scheme+host+"/") || strings.Contains(commandText, scheme+host+":") || strings.Contains(commandText, scheme+host+" ") {
					return true
				}
			}
		}
	}
	return false
}

func inClusterServiceDNSName(value string) (string, string, bool) {
	parts := strings.Split(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), "."), ".")
	if len(parts) != 5 || parts[2] != "svc" || parts[3] != "cluster" || parts[4] != "local" {
		return "", "", false
	}
	return parts[1], parts[0], true
}

func objectReferenceMatches(reference *corev1.ObjectReference, pod *corev1.Pod, defaultNamespace string) bool {
	if reference == nil || pod == nil {
		return false
	}
	if reference.Kind != "" && !strings.EqualFold(reference.Kind, "Pod") {
		return false
	}
	namespace := reference.Namespace
	if namespace == "" {
		namespace = defaultNamespace
	}
	if namespace != pod.Namespace || reference.Name != pod.Name {
		return false
	}
	return reference.UID == "" || pod.UID == "" || reference.UID == pod.UID
}

func endpointSliceTargetsPod(slice *discoveryv1.EndpointSlice, pod *corev1.Pod, podIPs map[string]struct{}) bool {
	if slice.Namespace != pod.Namespace {
		return false
	}
	for _, endpoint := range slice.Endpoints {
		if objectReferenceMatches(endpoint.TargetRef, pod, slice.Namespace) {
			return true
		}
		for _, address := range endpoint.Addresses {
			if _, exists := podIPs[address]; exists {
				return true
			}
		}
	}
	return false
}

func endpointsTargetPod(endpoints *corev1.Endpoints, pod *corev1.Pod, podIPs map[string]struct{}) bool {
	if endpoints.Namespace != pod.Namespace {
		return false
	}
	for _, subset := range endpoints.Subsets {
		addresses := append(append([]corev1.EndpointAddress{}, subset.Addresses...), subset.NotReadyAddresses...)
		for _, address := range addresses {
			if objectReferenceMatches(address.TargetRef, pod, endpoints.Namespace) {
				return true
			}
			if _, exists := podIPs[address.IP]; exists {
				return true
			}
		}
	}
	return false
}

func filterServices(values []corev1.Service, names map[string]struct{}) []corev1.Service {
	result := []corev1.Service{}
	for _, value := range values {
		if _, exists := names[namespacedName(value.Namespace, value.Name)]; exists {
			result = append(result, value)
		}
	}
	return result
}

func filterEndpointSlices(values []discoveryv1.EndpointSlice, names map[string]struct{}, pod *corev1.Pod, podIPs map[string]struct{}) []discoveryv1.EndpointSlice {
	result := []discoveryv1.EndpointSlice{}
	for i := range values {
		value := values[i]
		serviceName := value.Labels[discoveryv1.LabelServiceName]
		_, relatedService := names[namespacedName(value.Namespace, serviceName)]
		if relatedService || endpointSliceTargetsPod(&value, pod, podIPs) {
			result = append(result, value)
		}
	}
	return result
}

func filterEndpoints(values []corev1.Endpoints, names map[string]struct{}, pod *corev1.Pod, podIPs map[string]struct{}) []corev1.Endpoints {
	result := []corev1.Endpoints{}
	for i := range values {
		value := values[i]
		_, relatedService := names[namespacedName(value.Namespace, value.Name)]
		if relatedService || endpointsTargetPod(&value, pod, podIPs) {
			result = append(result, value)
		}
	}
	return result
}

func filterIngresses(values []networkingv1.Ingress, serviceNames map[string]struct{}) []networkingv1.Ingress {
	result := []networkingv1.Ingress{}
	for _, value := range values {
		if ingressUsesSelectedService(&value, serviceNames) {
			result = append(result, value)
		}
	}
	return result
}

func ingressUsesSelectedService(ingress *networkingv1.Ingress, serviceNames map[string]struct{}) bool {
	uses := func(backend networkingv1.IngressBackend) bool {
		if backend.Service == nil {
			return false
		}
		_, exists := serviceNames[namespacedName(ingress.Namespace, backend.Service.Name)]
		return exists
	}
	if ingress.Spec.DefaultBackend != nil && uses(*ingress.Spec.DefaultBackend) {
		return true
	}
	for _, rule := range ingress.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if uses(path.Backend) {
				return true
			}
		}
	}
	return false
}

func selectedPodPVCNames(pod *corev1.Pod) map[string]struct{} {
	result := map[string]struct{}{}
	for _, volume := range pod.Spec.Volumes {
		if volume.PersistentVolumeClaim != nil && volume.PersistentVolumeClaim.ClaimName != "" {
			result[volume.PersistentVolumeClaim.ClaimName] = struct{}{}
		}
		if volume.Ephemeral != nil {
			// Generic ephemeral volume claim names are defined as
			// <pod-name>-<volume-name> by Kubernetes.
			result[pod.Name+"-"+volume.Name] = struct{}{}
		}
	}
	return result
}

func selectedPodObjectReferences(pod *corev1.Pod) (map[string]struct{}, map[string]struct{}) {
	configMaps, secrets := map[string]struct{}{}, map[string]struct{}{}
	addContainer := func(container corev1.Container) {
		for _, from := range container.EnvFrom {
			if from.ConfigMapRef != nil && from.ConfigMapRef.Name != "" {
				configMaps[from.ConfigMapRef.Name] = struct{}{}
			}
			if from.SecretRef != nil && from.SecretRef.Name != "" {
				secrets[from.SecretRef.Name] = struct{}{}
			}
		}
		for _, env := range container.Env {
			if env.ValueFrom == nil {
				continue
			}
			if value := env.ValueFrom.ConfigMapKeyRef; value != nil && value.Name != "" {
				configMaps[value.Name] = struct{}{}
			}
			if value := env.ValueFrom.SecretKeyRef; value != nil && value.Name != "" {
				secrets[value.Name] = struct{}{}
			}
		}
	}
	for _, container := range pod.Spec.InitContainers {
		addContainer(container)
	}
	for _, container := range pod.Spec.Containers {
		addContainer(container)
	}
	for _, container := range pod.Spec.EphemeralContainers {
		addContainer(corev1.Container(container.EphemeralContainerCommon))
	}
	for _, reference := range pod.Spec.ImagePullSecrets {
		if reference.Name != "" {
			secrets[reference.Name] = struct{}{}
		}
	}
	for _, volume := range pod.Spec.Volumes {
		addSecretReference := func(reference *corev1.LocalObjectReference) {
			if reference != nil && reference.Name != "" {
				secrets[reference.Name] = struct{}{}
			}
		}
		if volume.ConfigMap != nil && volume.ConfigMap.Name != "" {
			configMaps[volume.ConfigMap.Name] = struct{}{}
		}
		if volume.Secret != nil && volume.Secret.SecretName != "" {
			secrets[volume.Secret.SecretName] = struct{}{}
		}
		if volume.Projected != nil {
			for _, source := range volume.Projected.Sources {
				if source.ConfigMap != nil && source.ConfigMap.Name != "" {
					configMaps[source.ConfigMap.Name] = struct{}{}
				}
				if source.Secret != nil && source.Secret.Name != "" {
					secrets[source.Secret.Name] = struct{}{}
				}
			}
		}
		if volume.CSI != nil {
			addSecretReference(volume.CSI.NodePublishSecretRef)
		}
		if volume.RBD != nil {
			addSecretReference(volume.RBD.SecretRef)
		}
		if volume.Cinder != nil {
			addSecretReference(volume.Cinder.SecretRef)
		}
		if volume.CephFS != nil {
			addSecretReference(volume.CephFS.SecretRef)
		}
		if volume.FlexVolume != nil {
			addSecretReference(volume.FlexVolume.SecretRef)
		}
		if volume.ISCSI != nil {
			addSecretReference(volume.ISCSI.SecretRef)
		}
		if volume.ScaleIO != nil {
			addSecretReference(volume.ScaleIO.SecretRef)
		}
		if volume.StorageOS != nil {
			addSecretReference(volume.StorageOS.SecretRef)
		}
		if volume.AzureFile != nil && volume.AzureFile.SecretName != "" {
			secrets[volume.AzureFile.SecretName] = struct{}{}
		}
	}
	return configMaps, secrets
}

func filterNetworkPolicies(values []networkingv1.NetworkPolicy, pod *corev1.Pod) []networkingv1.NetworkPolicy {
	result := []networkingv1.NetworkPolicy{}
	for i := range values {
		value := values[i]
		if value.Namespace != pod.Namespace {
			continue
		}
		selector, err := metav1.LabelSelectorAsSelector(&value.Spec.PodSelector)
		if err != nil || selector.Matches(labels.Set(pod.Labels)) {
			result = append(result, value)
		}
	}
	return result
}

func filterPodMetrics(values []unstructured.Unstructured, pod *corev1.Pod) []unstructured.Unstructured {
	result := []unstructured.Unstructured{}
	for _, value := range values {
		if value.GetNamespace() == pod.Namespace && value.GetName() == pod.Name {
			result = append(result, value)
		}
	}
	return result
}
