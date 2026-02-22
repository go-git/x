GOCMD  = go
GOTEST = $(GOCMD) test

# renovate: datasource=github-tags depName=golangci/golangci-lint
GOLANGCI_VERSION ?= v2.9.0

ROOT      := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TOOLS_BIN := $(shell mkdir -p $(ROOT)build/tools && realpath $(ROOT)build/tools)
GOLANGCI   = $(TOOLS_BIN)/golangci-lint-$(GOLANGCI_VERSION)
$(GOLANGCI):
	rm -f $(TOOLS_BIN)/golangci-lint*
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_VERSION)/install.sh | sh -s -- -b $(TOOLS_BIN) $(GOLANGCI_VERSION)
	mv $(TOOLS_BIN)/golangci-lint $(TOOLS_BIN)/golangci-lint-$(GOLANGCI_VERSION)

MODULES := $(shell find $(ROOT) -mindepth 2 -name "go.mod" -exec dirname {} \; | sort)

test:
	@for dir in $(MODULES); do \
		(cd $$dir && $(GOTEST) -race ./...) || exit 1; \
	done

validate: validate-lint validate-dirty

validate-lint: $(GOLANGCI)
	@for dir in $(MODULES); do \
		(cd $$dir && $(GOLANGCI) run) || exit 1; \
	done

validate-dirty:
ifneq ($(shell git status --porcelain --untracked-files=no),)
	@echo worktree is dirty
	@git --no-pager status
	@git --no-pager diff
	@exit 1
endif
