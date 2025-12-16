package extensionserver

import (
	"log/slog"

	pb "github.com/envoyproxy/gateway/proto/extension"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Server struct {
	pb.UnimplementedEnvoyGatewayExtensionServer

	log    *slog.Logger
	client client.Client
}

func New(logger *slog.Logger, client client.Client) *Server {
	return &Server{
		log:    logger,
		client: client,
	}
}
