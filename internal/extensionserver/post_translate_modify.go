package extensionserver

import (
	"context"

	pb "github.com/envoyproxy/gateway/proto/extension"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/giantswarm/envoy-extension-server-app/api/v1alpha1"
)

func (s *Server) PostTranslateModify(ctx context.Context, req *pb.PostTranslateModifyRequest) (*pb.PostTranslateModifyResponse, error) {
	s.log.Info("PostTranslateModify callback was invoked")

	// Fetch all CertificatePolicies from the cluster
	policies, err := s.listCertificatePolicies(ctx)
	if err != nil {
		s.log.Error("failed to list CertificatePolicies", "error", err)
		return &pb.PostTranslateModifyResponse{
			Secrets: req.Secrets,
		}, nil
	}

	s.log.Info("fetched CertificatePolicies", "count", len(policies))
	for _, policy := range policies {
		s.log.Info("found CertificatePolicy",
			"name", policy.Name,
			"namespace", policy.Namespace,
			"secretName", policy.Spec.SecretName,
		)
	}

	return &pb.PostTranslateModifyResponse{
		Secrets: req.Secrets,
	}, nil
}

// listCertificatePolicies fetches all CertificatePolicies from the cluster.
func (s *Server) listCertificatePolicies(ctx context.Context) ([]v1alpha1.CertificatePolicy, error) {
	var policyList v1alpha1.CertificatePolicyList
	if err := s.client.List(ctx, &policyList, &client.ListOptions{}); err != nil {
		return nil, err
	}
	return policyList.Items, nil
}
