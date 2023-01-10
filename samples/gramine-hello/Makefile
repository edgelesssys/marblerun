EDG_MARBLE_TYPE ?= hello

all: sign
.PHONY: clean all


sign: hello.manifest hello premain-libos
	gramine-sgx-sign --output hello.manifest.sgx --manifest hello.manifest --key enclave-key.pem
	gramine-sgx-get-token --sig hello.sig --output hello.token


clean:
	rm -f *.sig *.token *.manifest.sgx hello hello.manifest uuid


hello: hello.c
	$(CC) -Os -o$@ $<


hello.manifest: hello.manifest.template
	gramine-manifest $< > $@


premain-libos:
	wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-libos
	chmod u+x premain-libos

run:
	EDG_MARBLE_TYPE=$(EDG_MARBLE_TYPE) gramine-sgx hello
