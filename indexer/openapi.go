package indexer

//go:generate sh -c "cd cmd/oapigen && go run generator.go ../../indexer_opanapi_v1.yaml"
//go:generate oapi-codegen -config client-codegen.yaml indexer_opanapi_v1.yaml
//go:generate sh -c "./generate-docs.sh"
