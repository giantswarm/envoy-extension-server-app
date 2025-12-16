package extensionserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	pb "github.com/envoyproxy/gateway/proto/extension"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/giantswarm/envoy-extension-server-app/api/v1alpha1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestServer() *Server {
	return New(slog.New(slog.NewTextHandler(os.Stdout, nil)), nil)
}

func TestExtractCertificatePolicies(t *testing.T) {
	server := newTestServer()

	tests := []struct {
		name       string
		extensions []*pb.ExtensionResource
		wantCount  int
		wantNames  []string
	}{
		{
			name:       "empty extensions",
			extensions: nil,
			wantCount:  0,
			wantNames:  nil,
		},
		{
			name: "single policy",
			extensions: []*pb.ExtensionResource{
				createExtensionResource(t, "secret-1"),
			},
			wantCount: 1,
			wantNames: []string{"secret-1"},
		},
		{
			name: "multiple policies",
			extensions: []*pb.ExtensionResource{
				createExtensionResource(t, "secret-1"),
				createExtensionResource(t, "secret-2"),
				createExtensionResource(t, "secret-3"),
			},
			wantCount: 3,
			wantNames: []string{"secret-1", "secret-2", "secret-3"},
		},
		{
			name: "invalid extension is skipped",
			extensions: []*pb.ExtensionResource{
				createExtensionResource(t, "secret-1"),
				{UnstructuredBytes: []byte("invalid json")},
				createExtensionResource(t, "secret-2"),
			},
			wantCount: 2,
			wantNames: []string{"secret-1", "secret-2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policies := server.extractCertificatePolicies(tt.extensions)

			if len(policies) != tt.wantCount {
				t.Errorf("extractCertificatePolicies() returned %d policies, want %d", len(policies), tt.wantCount)
			}

			for i, wantName := range tt.wantNames {
				if policies[i].Spec.SecretName != wantName {
					t.Errorf("policy[%d].Spec.SecretName = %q, want %q", i, policies[i].Spec.SecretName, wantName)
				}
			}
		})
	}
}

func TestExtractDownstreamTlsContext(t *testing.T) {
	tests := []struct {
		name            string
		transportSocket *corev3.TransportSocket
		wantErr         bool
	}{
		{
			name:            "valid TLS context",
			transportSocket: createTransportSocketWithTLS(t),
			wantErr:         false,
		},
		{
			name: "invalid typed config",
			transportSocket: &corev3.TransportSocket{
				Name: "envoy.transport_sockets.tls",
				ConfigType: &corev3.TransportSocket_TypedConfig{
					TypedConfig: mustAny(t, &corev3.Node{}),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractDownstreamTlsContext(tt.transportSocket)

			if (err != nil) != tt.wantErr {
				t.Errorf("extractDownstreamTlsContext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == nil {
				t.Error("extractDownstreamTlsContext() returned nil result without error")
			}
		})
	}
}

func TestAppendSdsSecretConfigs(t *testing.T) {
	tests := []struct {
		name            string
		tlsContext      *tlsv3.DownstreamTlsContext
		policies        []v1alpha1.CertificatePolicy
		wantConfigCount int
		wantSecretNames []string
	}{
		{
			name:            "nil CommonTlsContext gets initialized",
			tlsContext:      &tlsv3.DownstreamTlsContext{},
			policies:        []v1alpha1.CertificatePolicy{createPolicy("secret-1")},
			wantConfigCount: 1,
			wantSecretNames: []string{"secret-1"},
		},
		{
			name: "appends to existing configs",
			tlsContext: &tlsv3.DownstreamTlsContext{
				CommonTlsContext: &tlsv3.CommonTlsContext{
					TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{
						{Name: "existing-secret"},
					},
				},
			},
			policies:        []v1alpha1.CertificatePolicy{createPolicy("new-secret")},
			wantConfigCount: 2,
			wantSecretNames: []string{"existing-secret", "new-secret"},
		},
		{
			name:            "multiple policies",
			tlsContext:      &tlsv3.DownstreamTlsContext{},
			policies:        []v1alpha1.CertificatePolicy{createPolicy("secret-1"), createPolicy("secret-2")},
			wantConfigCount: 2,
			wantSecretNames: []string{"secret-1", "secret-2"},
		},
		{
			name:            "empty policies",
			tlsContext:      &tlsv3.DownstreamTlsContext{},
			policies:        []v1alpha1.CertificatePolicy{},
			wantConfigCount: 0,
			wantSecretNames: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appendSdsSecretConfigs(tt.tlsContext, tt.policies)

			configs := tt.tlsContext.CommonTlsContext.TlsCertificateSdsSecretConfigs
			if len(configs) != tt.wantConfigCount {
				t.Errorf("got %d configs, want %d", len(configs), tt.wantConfigCount)
			}

			for i, wantName := range tt.wantSecretNames {
				if configs[i].Name != wantName {
					t.Errorf("config[%d].Name = %q, want %q", i, configs[i].Name, wantName)
				}
			}
		})
	}
}

func TestUpdateTransportSocket(t *testing.T) {
	transportSocket := createTransportSocketWithTLS(t)
	tlsContext := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{
			TlsCertificateSdsSecretConfigs: []*tlsv3.SdsSecretConfig{
				{Name: "test-secret"},
			},
		},
	}

	err := updateTransportSocket(transportSocket, tlsContext)
	if err != nil {
		t.Fatalf("updateTransportSocket() error = %v", err)
	}

	// Verify the transport socket was updated
	if transportSocket.GetTypedConfig() == nil {
		t.Error("transport socket TypedConfig is nil after update")
	}

	// Unmarshal and verify
	result := &tlsv3.DownstreamTlsContext{}
	if err := transportSocket.GetTypedConfig().UnmarshalTo(result); err != nil {
		t.Fatalf("failed to unmarshal updated config: %v", err)
	}

	if len(result.CommonTlsContext.TlsCertificateSdsSecretConfigs) != 1 {
		t.Errorf("expected 1 SDS config, got %d", len(result.CommonTlsContext.TlsCertificateSdsSecretConfigs))
	}
}

func TestApplyPoliciesToFilterChain(t *testing.T) {
	server := newTestServer()

	tests := []struct {
		name        string
		filterChain *listenerv3.FilterChain
		policies    []v1alpha1.CertificatePolicy
		wantErr     bool
	}{
		{
			name: "nil transport socket returns nil",
			filterChain: &listenerv3.FilterChain{
				TransportSocket: nil,
			},
			policies: []v1alpha1.CertificatePolicy{createPolicy("secret-1")},
			wantErr:  false,
		},
		{
			name: "applies policies to valid filter chain",
			filterChain: &listenerv3.FilterChain{
				TransportSocket: createTransportSocketWithTLS(t),
			},
			policies: []v1alpha1.CertificatePolicy{createPolicy("secret-1"), createPolicy("secret-2")},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.applyPoliciesToFilterChain(tt.filterChain, tt.policies)

			if (err != nil) != tt.wantErr {
				t.Errorf("applyPoliciesToFilterChain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPostHTTPListenerModify(t *testing.T) {
	server := newTestServer()

	tests := []struct {
		name    string
		req     *pb.PostHTTPListenerModifyRequest
		wantErr bool
	}{
		{
			name: "empty request",
			req: &pb.PostHTTPListenerModifyRequest{
				Listener: &listenerv3.Listener{},
				PostListenerContext: &pb.PostHTTPListenerExtensionContext{
					ExtensionResources: nil,
				},
			},
			wantErr: false,
		},
		{
			name: "with policies and filter chains",
			req: &pb.PostHTTPListenerModifyRequest{
				Listener: &listenerv3.Listener{
					FilterChains: []*listenerv3.FilterChain{
						{TransportSocket: createTransportSocketWithTLS(t)},
					},
				},
				PostListenerContext: &pb.PostHTTPListenerExtensionContext{
					ExtensionResources: []*pb.ExtensionResource{
						createExtensionResource(t, "secret-1"),
						createExtensionResource(t, "secret-2"),
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.PostHTTPListenerModify(context.Background(), tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("PostHTTPListenerModify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if resp == nil {
				t.Error("PostHTTPListenerModify() returned nil response")
				return
			}

			if resp.Listener == nil {
				t.Error("PostHTTPListenerModify() returned nil Listener")
			}
		})
	}
}

// Helper functions

func createExtensionResource(t *testing.T, secretName string) *pb.ExtensionResource {
	t.Helper()
	policy := createPolicy(secretName)
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}
	return &pb.ExtensionResource{
		UnstructuredBytes: data,
	}
}

func createPolicy(secretName string) v1alpha1.CertificatePolicy {
	return v1alpha1.CertificatePolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "example.extensions.io/v1alpha1",
			Kind:       "CertificatePolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.CertificatePolicySpec{
			SecretName: secretName,
		},
	}
}

func createTransportSocketWithTLS(t *testing.T) *corev3.TransportSocket {
	t.Helper()
	tlsContext := &tlsv3.DownstreamTlsContext{
		CommonTlsContext: &tlsv3.CommonTlsContext{},
	}
	return &corev3.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &corev3.TransportSocket_TypedConfig{
			TypedConfig: mustAny(t, tlsContext),
		},
	}
}

func mustAny(t *testing.T, msg proto.Message) *anypb.Any {
	t.Helper()
	any, err := anypb.New(msg)
	if err != nil {
		t.Fatalf("failed to create Any: %v", err)
	}
	return any
}
