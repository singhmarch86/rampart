# gRPC probe

A tiny gRPC server (the standard health service, with a unary `Check` and a
server-streaming `Watch`) and a client, used to test gRPC through Rampart.
Separate Go module so the proxy does not depend on gRPC. Results:
[docs/DETECTION.md](../../docs/DETECTION.md#grpc-and-protobuf-not-supported)
and [docs/FINDINGS.md #17](../../docs/FINDINGS.md).

```sh
cd scripts/grpc-probe
go build -o /tmp/grpc-server ./server && go build -o /tmp/grpc-client ./client
/tmp/grpc-server &                                   # 127.0.0.1:19101
/tmp/grpc-client                                     # direct: works
# point a Rampart (upstream http://127.0.0.1:19101) at it, then:
/tmp/grpc-client -target 127.0.0.1:8080 -tls         # via Rampart with TLS
/tmp/grpc-client -target 127.0.0.1:8080              # via Rampart, plain HTTP
```

Local use only: point it at systems you own.
