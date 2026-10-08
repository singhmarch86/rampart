package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func main() {
	target := flag.String("target", "127.0.0.1:19101", "")
	useTLS := flag.Bool("tls", false, "")
	svc := flag.String("svc", "svc", "service name in the request")
	flag.Parse()
	var cred grpc.DialOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	if *useTLS {
		cred = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}))
	}
	conn, err := grpc.NewClient(*target, cred)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	defer conn.Close()
	c := healthpb.NewHealthClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	r, err := c.Check(ctx, &healthpb.HealthCheckRequest{Service: *svc})
	if err != nil {
		fmt.Printf("unary Check:     FAIL code=%v msg=%q\n", status.Code(err), status.Convert(err).Message())
	} else {
		fmt.Printf("unary Check:     OK status=%v\n", r.Status)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel2()
	st, err := c.Watch(ctx2, &healthpb.HealthCheckRequest{Service: *svc})
	if err != nil {
		fmt.Printf("server-stream Watch: FAIL open %v\n", err)
		return
	}
	n := 0
	var first, last time.Time
	start := time.Now()
	for {
		m, err := st.Recv()
		if err != nil {
			fmt.Printf("server-stream Watch: received %d messages, ended with code=%v msg=%q\n", n, status.Code(err), status.Convert(err).Message())
			if n > 0 {
				fmt.Printf("  first message after %v, last after %v\n", first.Sub(start).Round(time.Millisecond), last.Sub(start).Round(time.Millisecond))
			}
			return
		}
		n++
		if n == 1 {
			first = time.Now()
		}
		last = time.Now()
		_ = m
	}
}
