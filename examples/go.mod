module github.com/nttcom/pola/examples

go 1.27.1

require (
	github.com/nttcom/pola v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260825221802-da73d73af1c5 // indirect
)

replace github.com/nttcom/pola => ../
