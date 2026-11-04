module github.com/nttcom/pola/examples

go 1.27.3

replace github.com/nttcom/pola => ../

require (
	github.com/nttcom/pola v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.85.0
	google.golang.org/protobuf v1.36.13-0.20261016172727-e9ee2a76ab8e
)

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261012220534-4341edf3f941 // indirect
)
