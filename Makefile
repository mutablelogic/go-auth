# Go parameters
GO=$(shell command -v go)
BUILDDIR=build
WASM=$(patsubst %/wasmbuild.yaml,%,$(wildcard wasm/*/wasmbuild.yaml))
CMD_DIRS=$(patsubst %/,%,$(wildcard cmd/*/))
CMD_BINS=$(patsubst cmd/%,$(BUILDDIR)/%,$(CMD_DIRS))
NPM_DIRS=$(patsubst %/package.json,%,$(wildcard npm/*/package.json))
NPM=$(patsubst %, %/dist/bundle.js,$(NPM_DIRS))
GOWASM=$(shell command -v go)
GOBIN=$(abspath $(BUILDDIR))
GOFILES=$(shell find . -name '*.go' -not -path './build/*' -not -path './.git/*') go.mod go.sum

# LDFLAGS
LD_FLAGS=-s -w

# All targets
all: wasmbuild $(WASM) $(NPM)

## BUILDING ###################################################################

.PHONY: wasm 
wasm: $(WASM)

.PHONY: cmd
cmd: $(CMD_BINS)

$(CMD_BINS): $(GOFILES) | go-dep
	@echo "Building $(patsubst $(BUILDDIR)/%,cmd/%,$@)"
	@$(GO) build -ldflags "$(LD_FLAGS)" -o $@ ./$(patsubst $(BUILDDIR)/%,cmd/%,$@)

define cmd-alias-rule
$(1): $(BUILDDIR)/$(notdir $(1))
	@true
endef

$(foreach dir,$(CMD_DIRS),$(eval $(call cmd-alias-rule,$(dir))))

# Rules for building
$(WASM): $(NPM) wasmbuild gowasm-dep
	@$(BUILDDIR)/wasmbuild build --go=${GOWASM} --go-flags='-ldflags "$(LD_FLAGS)"' -o ${BUILDDIR}/$(notdir $@).wasm ./$@

.PHONY: wasmbuild
wasmbuild: go-dep
	@GOBIN=${GOBIN} ${GO} install github.com/djthorpe/go-wasmbuild/cmd/wasmbuild@latest

.PHONY: npm
npm: $(NPM)

define npm-rule
$(1)/dist/bundle.js: $(1)/package.json $(filter-out $(1)/dist/bundle.js,$(wildcard $(1)/*.js) $(wildcard $(1)/*.mjs) $(wildcard $(1)/*.css) $(wildcard $(1)/assets/*.css) $(wildcard $(1)/assets/*/*.ttf)) $(wildcard $(1)/package-lock.json) | npm-dep
	@echo "Building $(1)"
	@cd $(1) && npm run build
endef

$(foreach dir,$(NPM_DIRS),$(eval $(call npm-rule,$(dir))))

## DEPENNDENCIES #############################################################

.PHONY: npm-dep
npm-dep:
	@command -v npm >/dev/null 2>&1 || { echo 'Missing npm'; exit 1; }

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
	@rm -fr $(addsuffix /dist,$(NPM_DIRS))
	@rm -f wasm/carbon-app/content/icon_names.go
	$(GO) clean
