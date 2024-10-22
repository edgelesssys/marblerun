EDG_MARBLE_TYPE ?= hello

all: sign
.PHONY: clean all

sign: hello.manifest
	gramine-sgx-sign --output hello.manifest.sgx --manifest hello.manifest --key enclave-key.pem

clean:
	rm -f *.sig *.token *.manifest.sgx hello hello.manifest uuid

hello: hello.c
	$(CC) -Os -o$@ $<

hello.manifest: hello.manifest.template hello premain-libos
	gramine-manifest $< > $@

premain-libos:
	wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-libos
	chmod u+x premain-libos

run:
	EDG_MARBLE_TYPE=$(EDG_MARBLE_TYPE) gramine-sgx hello
