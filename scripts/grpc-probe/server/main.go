package main

import (
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func main() {
	l, err := net.Listen("tcp", "127.0.0.1:19101")
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()
	h := health.NewServer()
	h.SetServingStatus("svc", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, h)
	reflection.Register(s)
	// flip status periodically so Watch (server streaming) emits updates
	go func() {
		st := healthpb.HealthCheckResponse_SERVING
		for {
			time.Sleep(500 * time.Millisecond)
			if st == healthpb.HealthCheckResponse_SERVING {
				st = healthpb.HealthCheckResponse_NOT_SERVING
			} else {
				st = healthpb.HealthCheckResponse_SERVING
			}
			h.SetServingStatus("svc", st)
		}
	}()
	log.Println("grpc server on 127.0.0.1:19101")
	log.Fatal(s.Serve(l))
}
