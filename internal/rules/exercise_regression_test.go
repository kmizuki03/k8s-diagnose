package rules

import (
	"context"
	"testing"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestExerciseGatewayAPIGaps(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "ns", Labels: map[string]string{"app": "api"}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Command: []string{"python", "-c"}, Args: []string{"if self.path == '/api/health': pass"}}}}}
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}}
	gateway := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
		"metadata": map[string]any{"name": "gw", "namespace": "ns"},
		"spec":     map[string]any{"gatewayClassName": "missing", "listeners": []any{map[string]any{"name": "http", "hostname": "other.example.test"}}},
	}}
	route := unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
		"metadata": map[string]any{"name": "route", "namespace": "ns"},
		"spec": map[string]any{"parentRefs": []any{map[string]any{"name": "gw"}}, "hostnames": []any{"app.example.test"}, "rules": []any{map[string]any{
			"matches":     []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/health"}}},
			"backendRefs": []any{map[string]any{"name": "api", "port": int64(80)}},
		}}},
	}}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, Services: []corev1.Service{service}, Gateways: []unstructured.Unstructured{gateway}, HTTPRoutes: []unstructured.Unstructured{route}}
	findings := (GatewayAPIRule{}).Evaluate(context.Background(), snapshot, config.Config{})
	for _, code := range []string{"K8S.GATEWAY.CLASS_NOT_FOUND", "K8S.HTTPROUTE.HOSTNAME_MISMATCH", "K8S.HTTPROUTE.PATH_BACKEND_MISMATCH"} {
		if !hasFindingCode(findings, code) {
			t.Errorf("%s が検出されない: %#v", code, findings)
		}
	}
	fixedGateway := *gateway.DeepCopy()
	fixedRoute := *route.DeepCopy()
	_ = unstructured.SetNestedField(fixedGateway.Object, "envoy", "spec", "gatewayClassName")
	_ = unstructured.SetNestedSlice(fixedGateway.Object, []any{map[string]any{"name": "http", "hostname": "app.example.test"}}, "spec", "listeners")
	_ = unstructured.SetNestedSlice(fixedRoute.Object, []any{map[string]any{"matches": []any{map[string]any{"path": map[string]any{"type": "PathPrefix", "value": "/api"}}}, "backendRefs": []any{map[string]any{"name": "api", "port": int64(80)}}}}, "spec", "rules")
	fixed := &kube.Snapshot{Pods: []corev1.Pod{pod}, Services: []corev1.Service{service}, GatewayClasses: []unstructured.Unstructured{{Object: map[string]any{"metadata": map[string]any{"name": "envoy"}}}}, Gateways: []unstructured.Unstructured{fixedGateway}, HTTPRoutes: []unstructured.Unstructured{fixedRoute}}
	for _, finding := range (GatewayAPIRule{}).Evaluate(context.Background(), fixed, config.Config{}) {
		if finding.Code == "K8S.GATEWAY.CLASS_NOT_FOUND" || finding.Code == "K8S.HTTPROUTE.HOSTNAME_MISMATCH" || finding.Code == "K8S.HTTPROUTE.PATH_BACKEND_MISMATCH" {
			t.Errorf("修正後に所見が残る: %#v", finding)
		}
	}
}

func TestExerciseNetworkAndServiceGaps(t *testing.T) {
	pods := []corev1.Pod{
		{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "ns", Labels: map[string]string{"role": "database"}}, Spec: corev1.PodSpec{NodeName: "worker"}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", Labels: map[string]string{"role": "app"}}, Spec: corev1.PodSpec{NodeName: "control", Containers: []corev1.Container{{Name: "client", Command: []string{"sh", "-c"}, Args: []string{"curl http://db/healthz"}}}}},
	}
	policy := networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "ns"}, Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"role": "database"}},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "backend"}}}}}},
	}}
	local := corev1.ServiceInternalTrafficPolicyLocal
	services := []corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"role": "database"}, InternalTrafficPolicy: &local}},
		{ObjectMeta: metav1.ObjectMeta{Name: "alias", Namespace: "ns"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "missing.ns.svc.cluster.local"}},
	}
	snapshot := &kube.Snapshot{Pods: pods, Services: services, NetworkPolicies: []networkingv1.NetworkPolicy{policy}, Nodes: []corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "control"}}, {ObjectMeta: metav1.ObjectMeta{Name: "worker"}}}}
	if !hasFindingCode((NetworkPolicyRule{}).Evaluate(context.Background(), snapshot, config.Config{}), "K8S.NETWORK_POLICY.PEER_SELECTOR_NO_MATCH") {
		t.Fatal("NetworkPolicy peer不一致が検出されない")
	}
	serviceFindings := (ServiceRule{}).Evaluate(context.Background(), snapshot, config.Config{})
	for _, code := range []string{"K8S.SERVICE.EXTERNAL_NAME_TARGET_NOT_FOUND", "K8S.SERVICE.INTERNAL_TRAFFIC_LOCAL_GAP"} {
		if !hasFindingCode(serviceFindings, code) {
			t.Errorf("%s が検出されない", code)
		}
	}
	policy.Spec.Ingress[0].From[0].PodSelector.MatchLabels["role"] = "app"
	cluster := corev1.ServiceInternalTrafficPolicyCluster
	services[0].Spec.InternalTrafficPolicy = &cluster
	services = append(services, corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "ns"}})
	fixedSnapshot := &kube.Snapshot{Pods: pods, Services: services, NetworkPolicies: []networkingv1.NetworkPolicy{policy}, Nodes: snapshot.Nodes}
	if hasFindingCode((NetworkPolicyRule{}).Evaluate(context.Background(), fixedSnapshot, config.Config{}), "K8S.NETWORK_POLICY.PEER_SELECTOR_NO_MATCH") {
		t.Fatal("修正後にもpeer不一致が残る")
	}
	fixedServiceFindings := (ServiceRule{}).Evaluate(context.Background(), fixedSnapshot, config.Config{})
	if hasFindingCode(fixedServiceFindings, "K8S.SERVICE.EXTERNAL_NAME_TARGET_NOT_FOUND") || hasFindingCode(fixedServiceFindings, "K8S.SERVICE.INTERNAL_TRAFFIC_LOCAL_GAP") {
		t.Fatal("修正後にもService所見が残る")
	}
}

func TestExerciseRuntimeDependencyGaps(t *testing.T) {
	runAs := int64(2000)
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Spec: corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "app-secret", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "secret"}}}, {Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}}},
		Containers: []corev1.Container{{Name: "app", SecurityContext: &corev1.SecurityContext{RunAsUser: &runAs}, Command: []string{"python", "-c"}, Args: []string{"cat('/etc/app-secret/token'); getaddrinfo(host); AF_INET6; sock.settimeout(timeout); sock.connect(addr)"}, VolumeMounts: []corev1.VolumeMount{{Name: "app-secret", MountPath: "/etc/wrong-secret"}, {Name: "data", MountPath: "/data"}}, Env: []corev1.EnvVar{
			{Name: "TARGET", Value: "typo.ns.svc.cluster.local"}, {Name: "DEPENDENCY_URL", Value: "http://dependency/ready"}, {Name: "CONNECT_TIMEOUT_SECONDS", Value: "1.0"},
			{Name: "SETTING", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Key: "SETTING"}}},
		}}},
	}}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "dependency", Namespace: "ns"}}}, ConfigMaps: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"}, Data: map[string]string{"SETTING": "old"}}}}
	findings := (RuntimeDependencyRule{}).Evaluate(context.Background(), snapshot, config.Config{})
	for _, code := range []string{"K8S.DEPENDENCY.ENV_SERVICE_NOT_FOUND", "K8S.DEPENDENCY.STARTUP_NOT_GATED", "K8S.CONFIG.CONNECT_TIMEOUT_HIGH", "K8S.CONFIGMAP.ENV_RESTART_REQUIRED", "K8S.PVC.NON_ROOT_WITHOUT_FSGROUP", "K8S.SECRET.MOUNT_PATH_MISMATCH"} {
		if !hasFindingCode(findings, code) {
			t.Errorf("%s が検出されない: %#v", code, findings)
		}
	}
	fixedPod := pod.DeepCopy()
	fsGroup := int64(2000)
	fixedPod.Spec.SecurityContext = &corev1.PodSecurityContext{FSGroup: &fsGroup}
	fixedPod.Spec.InitContainers = []corev1.Container{{Name: "wait"}}
	fixedPod.Spec.Containers[0].Command = []string{"cat", "/etc/app-secret/token"}
	fixedPod.Spec.Containers[0].VolumeMounts[0].MountPath = "/etc/app-secret"
	fixedPod.Spec.Containers[0].Env[0].Value = "real.ns.svc.cluster.local."
	fixedPod.Spec.Containers[0].Env[2].Value = "0.1"
	fixedPod.Annotations = map[string]string{"SETTING": "new"}
	fixedSnapshot := &kube.Snapshot{Pods: []corev1.Pod{*fixedPod}, Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "dependency", Namespace: "ns"}}, {ObjectMeta: metav1.ObjectMeta{Name: "real", Namespace: "ns"}}}, ConfigMaps: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"}, Data: map[string]string{"SETTING": "new"}}}}
	fixedFindings := (RuntimeDependencyRule{}).Evaluate(context.Background(), fixedSnapshot, config.Config{})
	for _, code := range []string{"K8S.DEPENDENCY.ENV_SERVICE_NOT_FOUND", "K8S.DEPENDENCY.STARTUP_NOT_GATED", "K8S.CONFIG.CONNECT_TIMEOUT_HIGH", "K8S.CONFIGMAP.ENV_RESTART_REQUIRED", "K8S.PVC.NON_ROOT_WITHOUT_FSGROUP", "K8S.SECRET.MOUNT_PATH_MISMATCH"} {
		if hasFindingCode(fixedFindings, code) {
			t.Errorf("修正後にも%sが残る: %#v", code, fixedFindings)
		}
	}
}

func TestExerciseCronJobWritesOutsideMountedVolume(t *testing.T) {
	cron := batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns"}, Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "backup", Command: []string{"sh", "-c"}, Args: []string{"mkdir -p /backup && date > /tmp/backup.txt"}, VolumeMounts: []corev1.VolumeMount{{Name: "backup", MountPath: "/backup"}}}}}}}}}}
	findings := (CronJobRule{}).Evaluate(context.Background(), &kube.Snapshot{CronJobs: []batchv1.CronJob{cron}}, config.Config{})
	if !hasFindingCode(findings, "K8S.CRONJOB.MOUNT_PATH_UNUSED") {
		t.Fatalf("書込先不一致が検出されない: %#v", findings)
	}
	cron.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Args[0] = "date > /backup/backup.txt"
	if hasFindingCode((CronJobRule{}).Evaluate(context.Background(), &kube.Snapshot{CronJobs: []batchv1.CronJob{cron}}, config.Config{}), "K8S.CRONJOB.MOUNT_PATH_UNUSED") {
		t.Fatal("修正後にも書込先不一致が残る")
	}
}

func TestHTTPRouteReadsParentConditions(t *testing.T) {
	route := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "route", "namespace": "ns"},
		"status": map[string]any{"parents": []any{map[string]any{
			"parentRef":  map[string]any{"name": "gateway"},
			"conditions": []any{map[string]any{"type": "ResolvedRefs", "status": "False", "reason": "BackendNotFound", "message": "missing"}},
		}}},
	}}
	if !hasFindingCode(routeConditionFindings(&route), "K8S.HTTPROUTE.CONDITION") {
		t.Fatal("status.parents[].conditions のResolvedRefs=Falseが検出されない")
	}
}

func TestRuntimeDependencyDoesNotGuessWhenConfigMapIsUnknownOrMissing(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "SETTING", ValueFrom: &corev1.EnvVarSource{ConfigMapKeyRef: &corev1.ConfigMapKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "settings"}, Key: "SETTING"}}}}}}}}
	for name, snapshot := range map[string]*kube.Snapshot{
		"取得不能": {Pods: []corev1.Pod{pod}, Statuses: map[string]kube.FetchStatus{"configmaps": {Available: false}}},
		"未作成":  {Pods: []corev1.Pod{pod}},
	} {
		t.Run(name, func(t *testing.T) {
			findings := (RuntimeDependencyRule{}).Evaluate(context.Background(), snapshot, config.Config{})
			if hasFindingCode(findings, "K8S.CONFIGMAP.ENV_RESTART_REQUIRED") {
				t.Fatalf("ConfigMapの値を確認できない状態で再起動所見を出した: %#v", findings)
			}
		})
	}
}

func TestNamespaceScopeDoesNotDeclareCrossNamespaceServiceMissing(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "app-ns"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "API", Value: "api.backend-ns.svc.cluster.local"}}}}}}
	namespaced := &kube.Snapshot{ScopeNamespace: "app-ns", Pods: []corev1.Pod{pod}}
	if hasFindingCode((RuntimeDependencyRule{}).Evaluate(context.Background(), namespaced, config.Config{}), "K8S.DEPENDENCY.ENV_SERVICE_NOT_FOUND") {
		t.Fatal("収集範囲外のServiceを不存在と断定した")
	}
	clusterWide := &kube.Snapshot{Pods: []corev1.Pod{pod}}
	if !hasFindingCode((RuntimeDependencyRule{}).Evaluate(context.Background(), clusterWide, config.Config{}), "K8S.DEPENDENCY.ENV_SERVICE_NOT_FOUND") {
		t.Fatal("cluster-wideで欠落しているServiceが検出されない")
	}
}

func TestLocalTrafficPolicyRequiresAffectedClient(t *testing.T) {
	local := corev1.ServiceInternalTrafficPolicyLocal
	service := corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}, InternalTrafficPolicy: &local}}
	server := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "server", Namespace: "ns", Labels: map[string]string{"app": "api"}}, Spec: corev1.PodSpec{NodeName: "worker"}, Status: corev1.PodStatus{Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
	unrelated := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: "ns"}, Spec: corev1.PodSpec{NodeName: "control", Containers: []corev1.Container{{Name: "app", Args: []string{"sleep 3600"}}}}}
	snapshot := &kube.Snapshot{Services: []corev1.Service{service}, Pods: []corev1.Pod{server, unrelated}}
	if hasFindingCode((ServiceRule{}).Evaluate(context.Background(), snapshot, config.Config{}), "K8S.SERVICE.INTERNAL_TRAFFIC_LOCAL_GAP") {
		t.Fatal("Serviceを利用しないPodしかいないNodeを障害扱いした")
	}
	snapshot.Pods[1].Spec.Containers[0].Args = []string{"curl http://api/healthz"}
	if !hasFindingCode((ServiceRule{}).Evaluate(context.Background(), snapshot, config.Config{}), "K8S.SERVICE.INTERNAL_TRAFFIC_LOCAL_GAP") {
		t.Fatal("EndpointのないNode上の利用Podを検出できない")
	}
}

func TestGatewayRuleKeepsNamespacedChecksWithoutGatewayClassAccess(t *testing.T) {
	meta := (GatewayAPIRule{}).Metadata()
	for _, required := range meta.Required {
		if required == "gatewayclasses" {
			t.Fatal("cluster-scoped GatewayClassをnamespaced診断の必須入力にしている")
		}
	}
}

func TestHTTPRouteCrossNamespaceBackendUsesDeclaredNamespace(t *testing.T) {
	route := unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "route", "namespace": "app-ns"},
		"spec":     map[string]any{"rules": []any{map[string]any{"backendRefs": []any{map[string]any{"name": "api", "namespace": "backend-ns"}}}}},
	}}
	namespaced := &kube.Snapshot{ScopeNamespace: "app-ns", HTTPRoutes: []unstructured.Unstructured{route}}
	if hasFindingCode((GatewayAPIRule{}).Evaluate(context.Background(), namespaced, config.Config{}), "K8S.HTTPROUTE.BACKEND_NOT_FOUND") {
		t.Fatal("収集範囲外のcross-namespace backendを不存在と断定した")
	}
	clusterWide := &kube.Snapshot{HTTPRoutes: []unstructured.Unstructured{route}, Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "backend-ns"}}}}
	if hasFindingCode((GatewayAPIRule{}).Evaluate(context.Background(), clusterWide, config.Config{}), "K8S.HTTPROUTE.BACKEND_NOT_FOUND") {
		t.Fatal("存在するcross-namespace backendを不存在と判定した")
	}
}

func TestConnectionTimeoutRequiresSequentialIPv6FallbackCode(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "CONNECT_TIMEOUT_SECONDS", Value: "30"}}, Args: []string{"server --listen :8080"}}}}}
	if hasFindingCode((RuntimeDependencyRule{}).Evaluate(context.Background(), &kube.Snapshot{Pods: []corev1.Pod{pod}}, config.Config{}), "K8S.CONFIG.CONNECT_TIMEOUT_HIGH") {
		t.Fatal("一般的な30秒タイムアウトを接続障害扱いした")
	}
}

func TestGatewayWildcardMatchesExactlyOneLabel(t *testing.T) {
	if !hostnameIntersects("*.example.com", "api.example.com") {
		t.Fatal("1ラベルのGateway wildcardが一致しない")
	}
	for _, hostname := range []string{"example.com", "v1.api.example.com", "*.api.example.com"} {
		if hostnameIntersects("*.example.com", hostname) {
			t.Fatalf("Gateway wildcardを複数または0ラベルへ過剰適用した: %s", hostname)
		}
	}
}

func TestDNSExpansionRequiresKnownNDots(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns"}, Spec: corev1.PodSpec{DNSPolicy: corev1.DNSDefault, Containers: []corev1.Container{{Name: "app", Env: []corev1.EnvVar{{Name: "API", Value: "api.ns.svc.cluster.local"}}}}}}
	snapshot := &kube.Snapshot{Pods: []corev1.Pod{pod}, Services: []corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "ns"}}}}
	if hasFindingCode((RuntimeDependencyRule{}).Evaluate(context.Background(), snapshot, config.Config{}), "K8S.DNS.FQDN_SEARCH_EXPANSION") {
		t.Fatal("dnsPolicy: Defaultの未知なndotsを5と決めつけた")
	}
	pod.Spec.DNSPolicy = corev1.DNSClusterFirst
	snapshot.Pods[0] = pod
	if !hasFindingCode((RuntimeDependencyRule{}).Evaluate(context.Background(), snapshot, config.Config{}), "K8S.DNS.FQDN_SEARCH_EXPANSION") {
		t.Fatal("ClusterFirstのndots:5候補を検出できない")
	}
}

func TestConfigMapRolloutIgnoresUnrelatedSecretChecksum(t *testing.T) {
	pod := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "ns", Annotations: map[string]string{"checksum/secret": "abc"}}}
	snapshot := &kube.Snapshot{ConfigMaps: []corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "settings", Namespace: "ns"}, Data: map[string]string{"SETTING": "new"}}}}
	if configMapRolloutTracked(&pod, "settings", "SETTING", snapshot) {
		t.Fatal("無関係なSecret checksumでConfigMap rollout追跡済みにした")
	}
	pod.Annotations["checksum/config"] = "def"
	if !configMapRolloutTracked(&pod, "settings", "SETTING", snapshot) {
		t.Fatal("ConfigMap用checksum annotationを認識できない")
	}
}

func TestCronJobWithoutExplicitRedirectIsNotDeclaredUnused(t *testing.T) {
	cron := batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns"}, Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "backup", Command: []string{"backup-tool"}, VolumeMounts: []corev1.VolumeMount{{Name: "data", MountPath: "/backup"}}}}}}}}}}
	if hasFindingCode((CronJobRule{}).Evaluate(context.Background(), &kube.Snapshot{CronJobs: []batchv1.CronJob{cron}}, config.Config{}), "K8S.CRONJOB.MOUNT_PATH_UNUSED") {
		t.Fatal("アプリ内部の書込先を確認できないCronJobを誤検出した")
	}
}

func hasFindingCode(findings []model.Finding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
