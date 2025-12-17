package extensionserver

import (
	"context"
	"encoding/json"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"

	pb "github.com/envoyproxy/gateway/proto/extension"

	"github.com/giantswarm/envoy-extension-server-app/api/v1alpha1"
)

// PostHTTPListenerModify is called after Envoy Gateway is done generating a
// Listener xDS configuration and before that configuration is passed on to
// Envoy Proxy.
func (s *Server) PostHTTPListenerModify(ctx context.Context, req *pb.PostHTTPListenerModifyRequest) (*pb.PostHTTPListenerModifyResponse, error) {
	s.log.Info("postHTTPListenerModify callback was invoked")

	policies := s.extractCertificatePolicies(req.PostListenerContext.ExtensionResources)

	for _, filterChain := range req.Listener.GetFilterChains() {
		if err := s.applyPoliciesToFilterChain(filterChain, policies); err != nil {
			s.log.Error("failed to apply policies to filter chain", "error", err)
		}
	}

	return &pb.PostHTTPListenerModifyResponse{
		Listener: req.Listener,
	}, nil
}

// extractCertificatePolicies unmarshals extension resources into CertificatePolicy objects.
func (s *Server) extractCertificatePolicies(extensions []*pb.ExtensionResource) []v1alpha1.CertificatePolicy {
	var policies []v1alpha1.CertificatePolicy
	for _, ext := range extensions {
		var certPolicy v1alpha1.CertificatePolicy
		if err := json.Unmarshal(ext.GetUnstructuredBytes(), &certPolicy); err != nil {
			s.log.Error("failed to unmarshal the extension", slog.String("error", err.Error()))
			continue
		}
		s.log.Info("processing an extension context", slog.String("secretName", certPolicy.Spec.SecretName))
		policies = append(policies, certPolicy)
	}
	return policies
}

// applyPoliciesToFilterChain adds SDS secret configs from policies to a filter chain's TLS context.
func (s *Server) applyPoliciesToFilterChain(filterChain *listenerv3.FilterChain, policies []v1alpha1.CertificatePolicy) error {
	transportSocket := filterChain.GetTransportSocket()
	if transportSocket == nil || transportSocket.GetTypedConfig() == nil {
		return nil
	}

	s.log.Info("transport socket", "transportSocket", transportSocket)

	downstreamTlsContext, err := extractDownstreamTlsContext(transportSocket)
	if err != nil {
		return err
	}

	appendSdsSecretConfigs(downstreamTlsContext, policies)

	return updateTransportSocket(transportSocket, downstreamTlsContext)
}

// extractDownstreamTlsContext unmarshals the transport socket config into a DownstreamTlsContext.
func extractDownstreamTlsContext(transportSocket *corev3.TransportSocket) (*tlsv3.DownstreamTlsContext, error) {
	downstreamTlsContext := &tlsv3.DownstreamTlsContext{}
	if err := transportSocket.GetTypedConfig().UnmarshalTo(downstreamTlsContext); err != nil {
		return nil, err
	}
	return downstreamTlsContext, nil
}

// appendSdsSecretConfigs adds SDS secret configs for each policy to the TLS context.
func appendSdsSecretConfigs(tlsContext *tlsv3.DownstreamTlsContext, policies []v1alpha1.CertificatePolicy) {
	if tlsContext.CommonTlsContext == nil {
		tlsContext.CommonTlsContext = &tlsv3.CommonTlsContext{}
	}
	if tlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs == nil {
		tlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs = []*tlsv3.SdsSecretConfig{}
	}

	for _, policy := range policies {
		newSdsConfig := NewSdsSecretConfig(policy.Spec.SecretName)
		tlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs = append(
			tlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs,
			newSdsConfig,
		)
	}
}

// updateTransportSocket marshals the TLS context back and updates the transport socket.
func updateTransportSocket(transportSocket *corev3.TransportSocket, tlsContext *tlsv3.DownstreamTlsContext) error {
	modifiedTypedConfig, err := anypb.New(tlsContext)
	if err != nil {
		return err
	}
	transportSocket.ConfigType = &corev3.TransportSocket_TypedConfig{
		TypedConfig: modifiedTypedConfig,
	}
	return nil
}
