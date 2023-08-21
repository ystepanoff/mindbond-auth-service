proto:
	protoc pkg/pb/*.proto --go_out=plugins=grpc:.

auth-service:
	go run cmd/main.go
