# Go parameters
GO=$(shell command -v go)
BUILDDIR=build
WASM=$(patsubst %/wasmbuild.yaml,%,$(wildcard wasm/*/wasmbuild.yaml))
GOWASM=$(shell command -v go)
GOBIN=$(abspath $(BUILDDIR))

# LDFLAGS
LD_FLAGS=-s -w

# All targets
all: wasmbuild $(WASM)

## BUILDING ###################################################################

.PHONY: wasm 
wasm: $(WASM)

# Rules for building
$(WASM): wasmbuild gowasm-dep
	@$(BUILDDIR)/wasmbuild build --go=${GOWASM} --go-flags='-ldflags "$(LD_FLAGS)"' -o ${BUILDDIR}/$(notdir $@).wasm ./$@

.PHONY: wasmbuild
wasmbuild: go-dep
	@GOBIN=${GOBIN} ${GO} install github.com/djthorpe/go-wasmbuild/cmd/wasmbuild@latest

## DEPENNDENCIES #############################################################

.PHONY: go-dep
go-dep: mkdir
	@command -v ${GO} >/dev/null 2>&1 || { echo 'Missing go compiler: ${GO}'; exit 1; }

.PHONY: gowasm-dep
gowasm-dep:
	@command -v ${GOWASM} >/dev/null 2>&1 || { echo 'Missing wasm compiler: ${GOWASM}'; exit 1; }
	@echo 'Using wasm compiler ${GOWASM}'

## TIDY and CLEAN #############################################################

.PHONY: mkdir
mkdir:
	@install -d $(BUILDDIR)

.PHONY: tidy
tidy: 
	$(GO) mod tidy

.PHONY: clean
clean: tidy
	@rm -fr $(BUILDDIR)
	@rm -f npm/carbon/bundle.js
	@rm -f wasm/carbon-app/content/icon_names.go
	$(GO) clean
