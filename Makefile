GO ?= go
BUILD ?= build

agent:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BUILD)/xiezhi-agent ./agent/cmd/xiezhi-agent

server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -o $(BUILD)/xiezhi-server ./server/cmd/xiezhi-server

build: agent server

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

.PHONY: agent server build test vet
