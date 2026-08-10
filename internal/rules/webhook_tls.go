package rules

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/kmizuki03/k8s-diagnose/internal/config"
	"github.com/kmizuki03/k8s-diagnose/internal/kube"
	"github.com/kmizuki03/k8s-diagnose/internal/model"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
)

type WebhookRule struct{}

func (WebhookRule) Metadata() Metadata {
	permissions := cluster("admissionregistration.k8s.io", "validatingwebhookconfigurations,mutatingwebhookconfigurations")
	permissions = append(permissions, namespaced("", "services")...)
	return Metadata{ID: "webhooks", Section: "Webhook", Description: "Admission WebhookのService参照", Required: []string{"validatingwebhooks", "mutatingwebhooks", "services"}, Permissions: permissions, Modes: []string{"all", "triage"}}
}

func (WebhookRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	serviceExists := func(namespace, name string) bool {
		for i := range snapshot.Services {
			if snapshot.Services[i].Namespace == namespace && snapshot.Services[i].Name == name {
				return true
			}
		}
		return false
	}
	check := func(kind, owner, name string, client admissionv1.WebhookClientConfig, policy *admissionv1.FailurePolicyType) {
		if client.Service == nil || serviceExists(client.Service.Namespace, client.Service.Name) {
			return
		}
		failurePolicy := admissionv1.Fail
		if policy != nil {
			failurePolicy = *policy
		}
		severity, confidence := model.Issue, 98
		if failurePolicy == admissionv1.Ignore {
			severity, confidence = model.Warning, 85
		}
		result = append(result, model.NewFinding(
			severity, "K8S.WEBHOOK.MISSING_SERVICE", "Webhook", ref(kind, "", owner), string(failurePolicy), name,
			fmt.Sprintf("%s %s / webhook %s: Service %s/%sが存在しません (failurePolicy=%s)", kind, owner, name, client.Service.Namespace, client.Service.Name, failurePolicy), confidence,
			model.Evidence{Kind: "reference", Key: "service", Value: shortRef(client.Service.Namespace, client.Service.Name)},
		))
	}
	for i := range snapshot.ValidatingWebhooks {
		item := &snapshot.ValidatingWebhooks[i]
		for _, webhook := range item.Webhooks {
			check("ValidatingWebhookConfiguration", item.Name, webhook.Name, webhook.ClientConfig, webhook.FailurePolicy)
		}
	}
	for i := range snapshot.MutatingWebhooks {
		item := &snapshot.MutatingWebhooks[i]
		for _, webhook := range item.Webhooks {
			check("MutatingWebhookConfiguration", item.Name, webhook.Name, webhook.ClientConfig, webhook.FailurePolicy)
		}
	}
	return result
}

type TLSRule struct{}

func (TLSRule) Metadata() Metadata {
	return Metadata{ID: "tls", Section: "TLS", Description: "TLS Secret内のX.509証明書", Required: []string{"secrets"}, Permissions: namespaced("", "secrets"), Modes: []string{"all", "triage"}}
}

func (TLSRule) Evaluate(_ context.Context, snapshot *kube.Snapshot, _ config.Config) []model.Finding {
	result := []model.Finding{}
	now := evaluationTime(snapshot)
	for _, secret := range snapshot.Secrets {
		if secret.Type != corev1.SecretTypeTLS && len(secret.TLSCert) == 0 {
			continue
		}
		resource := ref("Secret", secret.Namespace, secret.Name)
		if secret.Type == corev1.SecretTypeTLS && len(secret.TLSCert) == 0 {
			result = append(result, model.NewFinding(model.Issue, "K8S.TLS.SECRET_DATA_MISSING", "TLS", resource, "MissingTLSCertificate", corev1.TLSCertKey,
				fmt.Sprintf("Secret %s: %sが空または存在しません", shortRef(secret.Namespace, secret.Name), corev1.TLSCertKey), 100))
			continue
		}
		if secret.Type == corev1.SecretTypeTLS && secret.Keys != nil {
			if _, exists := secret.Keys[corev1.TLSPrivateKeyKey]; !exists {
				result = append(result, model.NewFinding(model.Issue, "K8S.TLS.SECRET_DATA_MISSING", "TLS", resource, "MissingTLSPrivateKey", corev1.TLSPrivateKeyKey,
					fmt.Sprintf("Secret %s: %sが存在しません", shortRef(secret.Namespace, secret.Name), corev1.TLSPrivateKeyKey), 100))
			}
		}
		if secret.TLSKeyPairError != "" {
			result = append(result, model.NewFinding(
				model.Issue, "K8S.TLS.KEY_PAIR_INVALID", "TLS", resource, "InvalidTLSKeyPair", "tls-key-pair",
				fmt.Sprintf("Secret %s: tls.crtとtls.keyの組み合わせが不正です", shortRef(secret.Namespace, secret.Name)), 100,
				model.Evidence{Kind: "x509", Key: "keyPairError", Value: secret.TLSKeyPairError},
			))
		}
		certificates, parseErrors := parseCertificateBundle(secret.TLSCert)
		for index, err := range parseErrors {
			result = append(result, model.NewFinding(
				model.Issue, "K8S.TLS.CERT_INVALID", "TLS", resource, "InvalidCertificate", fmt.Sprintf("certificate-%d", index+1),
				fmt.Sprintf("Secret %s: TLS証明書の形式を解析できません", shortRef(secret.Namespace, secret.Name)), 100,
				model.Evidence{Kind: "x509", Key: "error", Value: err.Error()},
			))
		}
		for index, certificate := range certificates {
			fingerprintBytes := sha256.Sum256(certificate.Raw)
			fingerprint := strings.ToUpper(hex.EncodeToString(fingerprintBytes[:]))
			label := shortRef(secret.Namespace, secret.Name)
			if len(certificates) > 1 {
				label = fmt.Sprintf("%s#cert-%d", label, index+1)
			}
			evidence := []model.Evidence{
				{Kind: "x509", Key: "notBefore", Value: certificate.NotBefore.UTC().Format(time.RFC3339)},
				{Kind: "x509", Key: "notAfter", Value: certificate.NotAfter.UTC().Format(time.RFC3339)},
				{Kind: "x509", Key: "subject", Value: certificate.Subject.String()},
				{Kind: "x509", Key: "issuer", Value: certificate.Issuer.String()},
			}
			switch {
			case certificate.NotBefore.After(now):
				result = append(result, model.NewFinding(model.Issue, "K8S.TLS.CERT_NOT_YET_VALID", "TLS", resource, "NotYetValid", fingerprint, fmt.Sprintf("TLS証明書 %s: 有効開始は%sです", label, certificate.NotBefore.Local().Format("2006-01-02 15:04:05")), 100, evidence...))
			case !certificate.NotAfter.After(now):
				result = append(result, model.NewFinding(model.Issue, "K8S.TLS.CERT_EXPIRED", "TLS", resource, "Expired", fingerprint, fmt.Sprintf("TLS証明書 %s: %sに期限切れしています", label, certificate.NotAfter.Local().Format("2006-01-02 15:04:05")), 100, evidence...))
			case certificate.NotAfter.Before(now.Add(30 * 24 * time.Hour)):
				result = append(result, model.NewFinding(model.Warning, "K8S.TLS.CERT_EXPIRING_SOON", "TLS", resource, "ExpiringSoon", fingerprint, fmt.Sprintf("TLS証明書 %s: %sに期限切れ予定です", label, certificate.NotAfter.Local().Format("2006-01-02 15:04:05")), 95, evidence...))
			}
		}
	}
	return result
}

func parseCertificateBundle(data []byte) ([]*x509.Certificate, []error) {
	certificates := []*x509.Certificate{}
	errorsFound := []error{}
	rest := data
	foundPEM := false
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		rest, foundPEM = remainder, true
		if block.Type != "CERTIFICATE" {
			continue
		}
		values, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			errorsFound = append(errorsFound, err)
			continue
		}
		certificates = append(certificates, values...)
	}
	if !foundPEM {
		values, err := x509.ParseCertificates(data)
		if err != nil {
			errorsFound = append(errorsFound, err)
		} else {
			certificates = append(certificates, values...)
		}
	}
	if foundPEM && len(certificates) == 0 && len(errorsFound) == 0 {
		errorsFound = append(errorsFound, fmt.Errorf("CERTIFICATE PEM blockがありません"))
	}
	if foundPEM && len(bytes.TrimSpace(rest)) > 0 {
		errorsFound = append(errorsFound, fmt.Errorf("PEM bundle末尾に解析できないデータがあります"))
	}
	return certificates, errorsFound
}
