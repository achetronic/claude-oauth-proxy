.PHONY: build run

build:
	go build -buildvcs=false -o bin/claude-oauth-proxy .

run:
	go run .
