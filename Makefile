# Executables
GO ?= $(shell which go 2>/dev/null)
DOCKER ?= $(shell which docker 2>/dev/null)

# Locations
BUILD_DIR ?= build
DIST_DIR ?= $(BUILD_DIR)/dist
WASMBUILD_SUBMODULE_DIR ?= third_party/go-wasmbuild

# Set OS and Architecture
ARCH ?= $(shell arch | tr A-Z a-z | sed 's/x86_64/amd64/' | sed 's/i386/amd64/' | sed 's/armv7l/arm/' | sed 's/aarch64/arm64/')
OS ?= $(shell uname | tr A-Z a-z)
VERSION ?= $(shell git describe --tags --always | sed 's/^v//')

# Set build flags
BUILD_MODULE = $(shell cat go.mod | head -1 | cut -d ' ' -f 2)
BUILD_VERSION_PACKAGE = github.com/mutablelogic/go-server/pkg/version
BUILD_LD_FLAGS += -X $(BUILD_VERSION_PACKAGE).GitTag=${VERSION}
BUILD_LD_FLAGS += -X $(BUILD_VERSION_PACKAGE).GitBranch=$(shell git name-rev HEAD --name-only --always)
BUILD_FLAGS = -ldflags "-s -w ${BUILD_LD_FLAGS}" 

# Docker
DOCKER_REPO ?= ghcr.io/mutablelogic/go-auth
DOCKER_SOURCE ?= ${BUILD_MODULE}
DOCKER_TAG = ${DOCKER_REPO}-${OS}-${ARCH}:${VERSION}

###############################################################################
# ALL

.PHONY: all
all: authmanager

###############################################################################
# BUILD

.PHONY: authmanager
authmanager: wasmbuild dist
	@echo Build authmanager GOOS=${OS} GOARCH=${ARCH}
	@${BUILD_DIR}/wasmbuild build -o ${BUILD_DIR}/app.wasm ./wasm/app
	@GOOS=${OS} GOARCH=${ARCH} ${GO} build ${BUILD_FLAGS} -o ${BUILD_DIR}/authmanager ./cmd/authmanager

.PHONY: client
client: go-dep
	@echo Build client GOOS=${OS} GOARCH=${ARCH}
	@GOOS=${OS} GOARCH=${ARCH} ${GO} build ${BUILD_FLAGS} -tags client -o ${BUILD_DIR}/authmanager ./cmd/authmanager

.PHONY: wasmbuild
wasmbuild: go-dep
	@GOBIN=$(abspath $(BUILD_DIR)) ${GO} install github.com/djthorpe/go-wasmbuild/cmd/wasmbuild@latest

.PHONY: submodule
submodule:
	@git submodule sync --recursive -- third_party
	@git submodule update --init --recursive -- third_party

.PHONY: dist
dist: carbon-dist auth-dist

.PHONY: carbon-dist
carbon-dist: npm-dep mkdir
	@echo Build Carbon assets into $(DIST_DIR)
	@$(MAKE) -C $(WASMBUILD_SUBMODULE_DIR) NPM_CARBON_DIST_DIR='$(abspath $(DIST_DIR))' npm/carbon

.PHONY: auth-dist
auth-dist: npm-dep mkdir
	@echo Build auth assets into $(DIST_DIR)
	@$(MAKE) -C $(WASMBUILD_SUBMODULE_DIR) NPM_AUTH_DIST_DIR='$(abspath $(DIST_DIR))' npm/auth

###############################################################################
# DOCKER

# Build the docker image
.PHONY: docker
docker: docker-dep 
	@echo build docker image ${DOCKER_TAG} OS=${OS} ARCH=${ARCH} SOURCE=${DOCKER_SOURCE} VERSION=${VERSION}
	@${DOCKER} build \
		--tag ${DOCKER_TAG} \
		--provenance=false \
		--build-arg ARCH=${ARCH} \
		--build-arg OS=${OS} \
		--build-arg SOURCE=${DOCKER_SOURCE} \
		--build-arg VERSION=${VERSION} \
		-f etc/docker/Dockerfile .

# Push docker container
.PHONY: docker-push
docker-push: docker-dep 
	@echo push docker image: ${DOCKER_TAG}
	@${DOCKER} push ${DOCKER_TAG}

# Print out the version
.PHONY: docker-version
docker-version: docker-dep 
	@echo "tag=${VERSION}"

## DEPENNDENCIES #############################################################

.PHONY: npm-dep
npm-dep:
	@command -v npm >/dev/null 2>&1 || { echo 'Missing npm'; exit 1; }

.PHONY: go-dep
go-dep: mkdir
	@command -v ${GO} >/dev/null 2>&1 || { echo 'Missing go compiler: ${GO}'; exit 1; }

.PHONY: docker-dep
docker-dep:
	@command -v ${DOCKER} >/dev/null 2>&1 || { echo "Missing docker binary"; exit 1; }

## TESTS ######################################################################

.PHONY: test
test: unittest

.PHONY: unittest
unittest: go-dep
	@$(GO) test ./...

## LICENSE ####################################################################

GOFILES_LICENSE=$(shell find . -name '*.go' -not -path './build/*' -not -path './.git/*' -not -path './npm/*')

.PHONY: license
license: go-dep
	@GOBIN=$(abspath $(BUILD_DIR)) ${GO} install github.com/google/addlicense@latest
	@${BUILD_DIR}/addlicense -c "David Thorpe" -l apache -y 2026 $(GOFILES_LICENSE)

## TIDY and CLEAN #############################################################

.PHONY: mkdir
mkdir:
	@install -d $(BUILD_DIR)

.PHONY: tidy
tidy: 
	$(GO) mod tidy

.PHONY: clean
clean: tidy
	@rm -fr $(BUILD_DIR)
	$(GO) clean
