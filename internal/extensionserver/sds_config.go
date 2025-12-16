package extensionserver

import (
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
)

// NewSdsSecretConfig creates a new SDS secret configuration with the given name.
func NewSdsSecretConfig(name string) *tlsv3.SdsSecretConfig {
	return &tlsv3.SdsSecretConfig{
		Name: name,
		SdsConfig: &corev3.ConfigSource{
			ResourceApiVersion: corev3.ApiVersion_V3,
			ConfigSourceSpecifier: &corev3.ConfigSource_Ads{
				Ads: &corev3.AggregatedConfigSource{},
			},
		},
	}
}
