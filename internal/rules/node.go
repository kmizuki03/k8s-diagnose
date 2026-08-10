package rules

import (
	"context"
	"fmt"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	corev1 "k8s.io/api/core/v1"
)

type NodeRule struct{}

func (NodeRule) Metadata() Metadata {
	return Metadata{ID: "nodes", Section: "Node", Description: "Node condition・volume・version", Required: []string{"nodes"}, Permissions: cluster("", "nodes"), Modes: []string{"all", "triage"}}
}

func (NodeRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	versions := map[string]int{}
	problemConditions := map[corev1.NodeConditionType]bool{
		corev1.NodeMemoryPressure: true, corev1.NodeDiskPressure: true,
		corev1.NodePIDPressure: true, corev1.NodeNetworkUnavailable: true,
	}
	for i := range snapshot.Nodes {
		node := &snapshot.Nodes[i]
		versions[node.Status.NodeInfo.KubeletVersion]++
		for _, c := range node.Status.Conditions {
			bad := c.Type == corev1.NodeReady && c.Status != corev1.ConditionTrue || problemConditions[c.Type] && c.Status == corev1.ConditionTrue
			if bad {
				result = append(result, model.NewFinding(
					model.Warning, "K8S.NODE.CONDITION", "Node", ref("Node", "", node.Name), string(c.Type), string(c.Type),
					fmt.Sprintf("Node %s: %s=%s (%s)", node.Name, c.Type, c.Status, c.Reason), 85,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
				continue
			}
			if c.Type != corev1.NodeReady && !problemConditions[c.Type] && c.Status == corev1.ConditionTrue {
				result = append(result, model.NewFinding(
					model.Candidate, "K8S.NODE.UNKNOWN_CONDITION", "Node", ref("Node", "", node.Name), string(c.Type), string(c.Type),
					fmt.Sprintf("Node %s: 独自condition %s=Trueです (意味は環境依存)", node.Name, c.Type), 35,
					model.Evidence{Kind: "condition", Key: string(c.Type), Value: c.Message},
				))
			}
		}
		attached := map[string]struct{}{}
		for _, volume := range node.Status.VolumesAttached {
			attached[string(volume.Name)] = struct{}{}
		}
		for _, volume := range node.Status.VolumesInUse {
			if _, ok := attached[string(volume)]; !ok {
				result = append(result, model.NewFinding(model.Warning, "K8S.NODE.VOLUME_STATE_MISMATCH", "Node", ref("Node", "", node.Name), "VolumeInUseNotAttached", string(volume), fmt.Sprintf("Node %s: volumesInUse %sがvolumesAttachedに存在しません", node.Name, volume), 75))
			}
		}
	}
	if len(versions) > 1 {
		result = append(result, model.NewFinding(model.Candidate, "K8S.NODE.KUBELET_VERSION_SKEW", "Node", "Cluster/kubelets", "VersionSkew", "kubelet-versions", fmt.Sprintf("kubeletVersionが%d種類存在します", len(versions)), 45))
	}
	return result
}

type NodeHeartbeatRule struct{}

func (NodeHeartbeatRule) Metadata() Metadata {
	return Metadata{
		ID: "node-heartbeats", Section: "Node", Description: "kube-node-leaseのNode heartbeat鮮度",
		Required: []string{"nodes", "node_leases"}, Permissions: cluster("coordination.k8s.io", "leases"),
		Modes: []string{"all", "triage"},
	}
}

func (NodeHeartbeatRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, cfg config.Config) []model.Finding {
	staleAfter := time.Duration(cfg.NodeHeartbeatTimeout) * time.Second
	referenceTime := evaluationTime(snapshot)
	leases := map[string]time.Time{}
	for i := range snapshot.NodeLeases {
		lease := &snapshot.NodeLeases[i]
		if lease.Spec.RenewTime != nil {
			leases[lease.Name] = lease.Spec.RenewTime.Time
		}
	}
	result := []model.Finding{}
	for i := range snapshot.Nodes {
		node := &snapshot.Nodes[i]
		renewed, exists := leases[node.Name]
		if !exists {
			// Node registration and kubelet Lease creation are separate API
			// writes. Give a newly-created Node one configured heartbeat window
			// before declaring the Lease missing.
			if !node.CreationTimestamp.IsZero() && referenceTime.Sub(node.CreationTimestamp.Time) < staleAfter {
				continue
			}
			result = append(result, model.NewFinding(
				model.Warning, "K8S.NODE.LEASE_MISSING", "Node", ref("Node", "", node.Name), "NodeLeaseMissing", "node-lease",
				fmt.Sprintf("Node %s: kube-node-leaseに対応するLeaseがありません", node.Name), 80,
			))
			continue
		}
		age := referenceTime.Sub(renewed)
		if age < -30*time.Second {
			result = append(result, model.NewFinding(
				model.Candidate, "K8S.NODE.HEARTBEAT_CLOCK_UNCERTAIN", "Node", ref("Node", "", node.Name), "LeaseTimeInFuture", "node-lease-clock",
				fmt.Sprintf("Node %s: Lease時刻がAPI Server基準より未来のため鮮度を確定できません", node.Name), 35,
				model.Evidence{Kind: "lease", Key: "renewTime", Value: renewed.UTC().Format(time.RFC3339)},
			))
			continue
		}
		if age <= staleAfter {
			continue
		}
		result = append(result, model.NewFinding(
			model.Warning, "K8S.NODE.HEARTBEAT_STALE", "Node", ref("Node", "", node.Name), "HeartbeatStale", "node-lease-renew-time",
			fmt.Sprintf("Node %s: Lease heartbeatが%d秒更新されていません", node.Name, int(age.Seconds())), 85,
			model.Evidence{Kind: "lease", Key: "renewTime", Value: renewed.UTC().Format(time.RFC3339)},
		))
	}
	return result
}
