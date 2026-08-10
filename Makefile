.PHONY: build test vet lint verify security supply-chain fmt clean

build:
	go build -mod=readonly -trimpath -ldflags "-s -w" -o k8s-diagnose .

test:
	go test -mod=readonly ./...

vet:
	go vet -mod=readonly ./...

lint:
	@command -v staticcheck >/dev/null || { echo 'staticcheck をインストールしてください'; exit 1; }
	staticcheck ./...
	staticcheck -tests=false ./...

verify:
	go mod verify
	go build -mod=readonly ./...

security:
	@command -v staticcheck >/dev/null || { echo 'staticcheck をインストールしてください'; exit 1; }
	@command -v govulncheck >/dev/null || { echo 'govulncheck をインストールしてください'; exit 1; }
	@command -v gosec >/dev/null || { echo 'gosec をインストールしてください'; exit 1; }
	staticcheck ./...
	staticcheck -tests=false ./...
	govulncheck ./...
	gosec ./...

supply-chain:
	@command -v cyclonedx-gomod >/dev/null || { echo 'cyclonedx-gomodをインストールしてください'; exit 1; }
	@command -v go-licenses >/dev/null || { echo 'go-licensesをインストールしてください'; exit 1; }
	./scripts/generate-supply-chain.sh

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

clean:
	rm -f ./k8s-diagnose
