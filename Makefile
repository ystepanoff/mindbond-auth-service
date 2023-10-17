proto:
	git clone git@flotta-home:mindbond/proto.git
	protoc proto/auth.proto --go_out=plugins=grpc:./pkg/pb/
	rm -rf proto/

auth-service:
	go run cmd/main.go
