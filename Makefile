.PHONY: build test clean install

build:
	go build -o network-recon .

test:
	go test ./...

clean:
	rm -f network-recon

install: build
	mkdir -p ~/.gibson/agents/bin
	cp network-recon ~/.gibson/agents/bin/
