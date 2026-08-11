.PHONY: build test vet lint verify security supply-chain package fmt clean fclean re

NAME := k8s-diagnose
GO_SOURCES := $(shell find . -type f -name '*.go' ! -name '*_test.go' ! -path './vendor/*' | sort)
BUILD_DEPS := $(GO_SOURCES) go.mod go.sum scripts/version.sh Makefile
VERSION ?= $(shell ./scripts/version.sh)
VERSION_SYMBOL := github.com/kmizuki03/k8s-diagnose/internal/config.Version
LDFLAGS ?= -s -w -X $(VERSION_SYMBOL)=$(VERSION)

build: $(NAME)

$(NAME): $(BUILD_DEPS)
	go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" -o $@ .

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
	go build -mod=readonly -trimpath -ldflags "$(LDFLAGS)" ./...

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

package:
	./scripts/package-release.sh

fmt:
	gofmt -w $$(find . -name '*.go' -type f)

clean:
	rm -f ./$(NAME)

fclean: clean
	rm -rf -- ./dist
	rm -f -- ./*.db ./*.db-shm ./*.db-wal ./*.db-journal ./*.out ./*.coverprofile ./coverage.* ./profile.cov

re: fclean
	$(MAKE) build
