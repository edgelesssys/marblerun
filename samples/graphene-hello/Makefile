GRAPHENEDIR?=$(HOME)/graphene
SIGNER=$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign
TOKEN=$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token

all: sign
.PHONY: clean all


sign: hello.manifest hello premain-graphene
	$(SIGNER) -output hello.manifest.sgx --libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so --manifest hello.manifest --key $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem
	$(TOKEN) -sig hello.sig -output hello.token


clean:
	rm -f *.sig *.token *.manifest.sgx hello hello.manifest uuid


hello: hello.c
	$(CC) -Os -o$@ $<


hello.manifest: hello.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' $< > $@


premain-graphene:
	wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-graphene


run:
	SGX=1 $(GRAPHENEDIR)/Runtime/pal_loader hello
