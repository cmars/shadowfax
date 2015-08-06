
BINARIES=$(GOPATH)/bin/sf $(GOPATH)/bin/sfd

TOOLS=$(GOPATH)/bin/godeps $(GOPATH)/bin/basen

all: deps install

install: $(BINARIES)

$(GOPATH)/bin/sf:
	go install ./cmd/sf

$(GOPATH)/bin/sfd:
	go install ./cmd/sfd

deps: tools
	godeps -u dependencies.tsv

tools: $(TOOLS)

$(GOPATH)/bin/godeps:
	go get launchpad.net/godeps

$(GOPATH)/bin/basen:
	go get gopkg.in/basen.v1/cmd/basen

test: deps install
	./ftests/pushpop.bash

clean:
	go clean ./...

all-clean: clean
	$(RM) $(BINARIES) $(TOOLS)

.PHONY: all deps tools clean all-clean

