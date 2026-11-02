.PHONY: build run test race vet tidy clean

build:
	go build -o bin/mhi ./cmd/mhi

run:
	go run ./cmd/mhi $(ARGS)

vet:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

tidy:
	go mod tidy

clean:
	rm -rf bin
