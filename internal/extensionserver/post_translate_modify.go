package extensionserver

import (
	"context"
	"fmt"

	pb "github.com/envoyproxy/gateway/proto/extension"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/giantswarm/envoy-extension-server-app/api/v1alpha1"
)

func (s *Server) PostTranslateModify(ctx context.Context, req *pb.PostTranslateModifyRequest) (*pb.PostTranslateModifyResponse, error) {
	s.log.Info("PostTranslateModify callback was invoked")

	// Log incoming request details
	s.log.Debug("request details",
		"clustersCount", len(req.GetClusters()),
		"secretsCount", len(req.GetSecrets()),
		"listenersCount", len(req.GetListeners()),
		"routesCount", len(req.GetRoutes()),
		"extensionResourcesCount", len(req.PostTranslateContext.GetExtensionResources()),
	)

	// Log existing secrets from the request
	for i, secret := range req.GetSecrets() {
		s.log.Debug("existing secret in request",
			"index", i,
			"name", secret.GetName(),
		)
	}

	// Extract CertificatePolicies from the request's extension resources
	policies := s.extractCertificatePolicies(req.PostTranslateContext.GetExtensionResources())

	s.log.Info("fetched CertificatePolicies", "count", len(policies))

	// Start with the existing secrets from the request
	secrets := req.Secrets

	// Fetch and add secrets referenced by each policy
	for _, policy := range policies {
		s.log.Info("processing CertificatePolicy",
			"name", policy.Name,
			"namespace", policy.Namespace,
			"secretName", policy.Spec.SecretName,
		)

		envoySecret, err := s.fetchAndConvertSecret(ctx, policy)
		if err != nil {
			s.log.Error("failed to fetch secret for policy",
				"policy", policy.Name,
				"secretName", policy.Spec.SecretName,
				"error", err,
			)
			continue
		}

		secrets = append(secrets, envoySecret)
		s.log.Info("added secret to response",
			"secretName", envoySecret.Name,
		)
	}

	// Log final response summary
	s.log.Debug("response summary",
		"totalSecretsCount", len(secrets),
		"addedSecretsCount", len(secrets)-len(req.GetSecrets()),
	)

	return &pb.PostTranslateModifyResponse{
		Secrets: secrets,
	}, nil
}

// fetchAndConvertSecret fetches a K8s TLS secret and converts it to an Envoy Secret.
func (s *Server) fetchAndConvertSecret(ctx context.Context, policy v1alpha1.CertificatePolicy) (*tlsv3.Secret, error) {
	var k8sSecret corev1.Secret
	secretKey := types.NamespacedName{
		Namespace: policy.Namespace,
		Name:      policy.Spec.SecretName,
	}

	if err := s.client.Get(ctx, secretKey, &k8sSecret); err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", secretKey.Namespace, secretKey.Name, err)
	}

	certChain, ok := k8sSecret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing %s key", secretKey.Namespace, secretKey.Name, corev1.TLSCertKey)
	}

	privateKey, ok := k8sSecret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s missing %s key", secretKey.Namespace, secretKey.Name, corev1.TLSPrivateKeyKey)
	}

	// Use namespace/name format for the Envoy secret name to ensure uniqueness
	envoySecretName := fmt.Sprintf("%s/%s", secretKey.Namespace, secretKey.Name)

	return &tlsv3.Secret{
		Name: envoySecretName,
		Type: &tlsv3.Secret_TlsCertificate{
			TlsCertificate: &tlsv3.TlsCertificate{
				CertificateChain: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{
						InlineBytes: certChain,
					},
				},
				PrivateKey: &corev3.DataSource{
					Specifier: &corev3.DataSource_InlineBytes{
						InlineBytes: privateKey,
					},
				},
			},
		},
	}, nil
}
