# Path parameters
GO ?= $(shell which go 2>/dev/null)
NPM ?= $(shell which npm 2>/dev/null)

# Locations
BUILD_DIR ?= build
CMD_DIR := $(filter-out cmd/_%,$(wildcard cmd/*))
TS_DIR := frontend

# The backend of the auth server: file (the default), pg, aws or bitwarden,
# which is its build tag, other than file
AUTH_CREDENTIALS_BACKEND ?= file
ifeq ($(filter $(AUTH_CREDENTIALS_BACKEND),file pg aws bitwarden),)
$(error AUTH_CREDENTIALS_BACKEND is $(AUTH_CREDENTIALS_BACKEND), but should be file, pg, aws or bitwarden)
endif

# The certificate manager, with AUTH_CERT=1, which is its build tag, cert.
# It needs PostgreSQL, which it shares with the pg backend.
AUTH_CERT ?=

# The commands embed the web UI, with the "frontend" tag, once it's built
# into frontend/app/dist, by make frontend, which needs npm, and a token which
# can read GitHub Packages, in GITHUB_TOKEN
comma := ,
TAGS = $(strip $(filter-out file,$(AUTH_CREDENTIALS_BACKEND)) $(if $(filter 1 yes true,$(AUTH_CERT)),cert,) $(if $(wildcard $(TS_DIR)/app/dist/index.html),frontend,))
BUILD_TAGS = $(if $(TAGS),-tags $(subst $() ,$(comma),$(TAGS)),)

# Set OS and Architecture
ARCH ?= $(shell arch | tr A-Z a-z | sed 's/x86_64/amd64/' | sed 's/i386/amd64/' | sed 's/armv7l/arm/' | sed 's/aarch64/arm64/')
OS ?= $(shell uname | tr A-Z a-z)
VERSION ?= $(shell git describe --tags --always | sed 's/^v//')

# Set build flags
VERSION_PKG = github.com/mutablelogic/go-server/pkg/version
BUILD_LD_FLAGS += -X $(VERSION_PKG).GitTag=$(shell git describe --tags --always)
BUILD_LD_FLAGS += -X $(VERSION_PKG).GitBranch=$(shell git name-rev HEAD --name-only --always)
BUILD_LD_FLAGS += -X $(VERSION_PKG).BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_FLAGS = -ldflags "-s -w ${BUILD_LD_FLAGS}"

###############################################################################
# ALL

.PHONY: all
all: build

###############################################################################
# BUILD

# Build the web UI, and then the commands in the cmd directory, which embed
# it, with the server's backend set by AUTH_CREDENTIALS_BACKEND, and the certificate
# manager by AUTH_CERT, such as make AUTH_CREDENTIALS_BACKEND=pg AUTH_CERT=1
.PHONY: build
build: frontend
	@$(MAKE) --no-print-directory tidy $(CMD_DIR)

$(CMD_DIR): go-dep mkdir
	@echo Build command $(notdir $@) GOOS=${OS} GOARCH=${ARCH} AUTH_CREDENTIALS_BACKEND=${AUTH_CREDENTIALS_BACKEND} AUTH_CERT=${AUTH_CERT}
	@GOOS=${OS} GOARCH=${ARCH} ${GO} build ${BUILD_TAGS} ${BUILD_FLAGS} -o ${BUILD_DIR}/$(notdir $@) ./$@

# Build the web UI's modules into frontend/dist, and the auth server's app
# into frontend/app/dist, from package-lock.json, once they're type checked
.PHONY: frontend
frontend: npm-dep
	@echo Build frontend
	@cd $(TS_DIR) && ${NPM} ci --silent && ${NPM} run --silent check && ${NPM} run --silent build && ${NPM} run --silent build-app

# Test the web UI
.PHONY: frontend-test
frontend-test: npm-dep
	@echo Frontend Tests
	@cd $(TS_DIR) && ${NPM} ci --silent && ${NPM} run --silent check && ${NPM} test --silent

# Build the auth command without the server, for clients
.PHONY: client
client: go-dep mkdir
	@echo Build client GOOS=${OS} GOARCH=${ARCH}
	@GOOS=${OS} GOARCH=${ARCH} ${GO} build -tags client ${BUILD_FLAGS} -o ${BUILD_DIR}/auth-client ./cmd/auth

###############################################################################
# TEST

.PHONY: test
test: unit-test coverage-test

# The credential/pg tests start a PostgreSQL container, so need docker
.PHONY: unit-test
unit-test: go-dep
	@echo Unit Tests
	@${GO} test ./...

# The LDAP tests start OpenLDAP, 389 DS and SMB LDS containers, from
# ldap/test, so need docker, and are skipped with -short. LDAP_TEST_SERVER
# chooses some of them, such as openldap,389ds. Results aren't cached, since
# the images and docker can change.
.PHONY: integration-test
integration-test: go-dep
	@echo Integration Tests
	@${GO} test -count=1 -timeout 20m ./ldap/...

.PHONY: coverage-test
coverage-test: go-dep mkdir
	@echo Test Coverage
	@${GO} test -coverprofile ${BUILD_DIR}/coverprofile.out ./...
	@${GO} tool cover -func ${BUILD_DIR}/coverprofile.out > ${BUILD_DIR}/coverage.txt

###############################################################################
# LICENSE

GOFILES_LICENSE = $(shell find . -name '*.go' -not -path './build/*' -not -path './.git/*' -not -path './_old/*')

# Add the license header to the Go files which don't have it
.PHONY: license
license: go-dep mkdir
	@GOBIN=$(abspath $(BUILD_DIR)) ${GO} install github.com/google/addlicense@latest
	@${BUILD_DIR}/addlicense -c "David Thorpe" -l apache -y 2026 $(GOFILES_LICENSE)

###############################################################################
# CLEAN

# Other rules
.PHONY: mkdir
mkdir:
	@install -d $(BUILD_DIR)

.PHONY: tidy
tidy: go-dep
	@echo 'go tidy'
	@$(GO) mod tidy

.PHONY: clean
clean: tidy
	@echo 'clean'
	@rm -fr $(BUILD_DIR) $(TS_DIR)/dist $(TS_DIR)/app/dist
	@$(GO) clean

###############################################################################
# DEPENDENCIES

.PHONY: go-dep
go-dep:
	@test -f "${GO}" && test -x "${GO}"  || (echo "Missing go binary" && exit 1)

.PHONY: npm-dep
npm-dep:
	@test -f "${NPM}" && test -x "${NPM}"  || (echo "Missing npm binary, which builds the web UI" && exit 1)
	@test -n "$${GITHUB_TOKEN}" || (echo "Missing GITHUB_TOKEN, which needs read:packages to install @mutablelogic packages from GitHub Packages" && exit 1)
