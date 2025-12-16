// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package extensionserver

import (
	"context"
	"encoding/json"
	"log/slog"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"google.golang.org/protobuf/types/known/anypb"

	pb "github.com/envoyproxy/gateway/proto/extension"
	"github.com/giantswarm/envoy-extension-server-app/api/v1alpha1"
)

// PostHTTPListenerModify is called after Envoy Gateway is done generating a
// Listener xDS configuration and before that configuration is passed on to
// Envoy Proxy.
// This example adds Basic Authentication on the Listener level as an example.
// Note: This implementation is not secure, and should not be used to protect
// anything important.
func (s *Server) PostHTTPListenerModify(ctx context.Context, req *pb.PostHTTPListenerModifyRequest) (*pb.PostHTTPListenerModifyResponse, error) {
	s.log.Info("postHTTPListenerModify callback was invoked")
	// Collect all CertificatePolicies from the extension resources attached to the gateway.
	var policies []v1alpha1.CertificatePolicy
	for _, ext := range req.PostListenerContext.ExtensionResources {
		var certPolicy v1alpha1.CertificatePolicy
		if err := json.Unmarshal(ext.GetUnstructuredBytes(), &certPolicy); err != nil {
			s.log.Error("failed to unmarshal the extension", slog.String("error", err.Error()))
			continue
		}
		s.log.Info("processing an extension context", slog.String("secretName", certPolicy.Spec.SecretName))
		policies = append(policies, certPolicy)
	}

	filterChains := req.Listener.GetFilterChains()
	for _, filterChain := range filterChains {
		transportSocket := filterChain.GetTransportSocket()

		s.log.Info("transport socket", "transportSocket", transportSocket)

		if transportSocket != nil && transportSocket.GetTypedConfig() != nil {
			// Unmarshal the typed config to DownstreamTlsContext
			downstreamTlsContext := &tlsv3.DownstreamTlsContext{}
			if err := transportSocket.GetTypedConfig().UnmarshalTo(downstreamTlsContext); err != nil {
				s.log.Error("failed to unmarshal DownstreamTlsContext", "error", err)
				continue
			}

			// Get or create CommonTlsContext
			if downstreamTlsContext.CommonTlsContext == nil {
				downstreamTlsContext.CommonTlsContext = &tlsv3.CommonTlsContext{}
			}

			// Initialize TlsCertificateSdsSecretConfigs if nil
			if downstreamTlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs == nil {
				downstreamTlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs = []*tlsv3.SdsSecretConfig{}
			}

			// Append SDS secret configs for each policy
			for _, policy := range policies {
				newSdsConfig := NewSdsSecretConfig(policy.Spec.SecretName)
				downstreamTlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs = append(
					downstreamTlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs,
					newSdsConfig,
				)
			}

			// Marshal the modified context back to Any
			modifiedTypedConfig, err := anypb.New(downstreamTlsContext)
			if err != nil {
				s.log.Error("failed to marshal DownstreamTlsContext", "error", err)
				continue
			}

			// Update the transport socket with the modified config
			transportSocket.ConfigType = &corev3.TransportSocket_TypedConfig{
				TypedConfig: modifiedTypedConfig,
			}

			s.log.Info("appended SDS secret configs to tls_certificate_sds_secret_configs", "count", len(policies))
		}
	}

	return &pb.PostHTTPListenerModifyResponse{
		Listener: req.Listener,
	}, nil
}
