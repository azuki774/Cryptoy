.PHONY: build
build:
	go build -o build/

.PHONY: test
test:
	go test -v ./...
