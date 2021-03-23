GRAPHENEDIR?=$(HOME)/graphene
SIGNER=$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-sign
TOKEN=$(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token

all: sign
.PHONY: clean all


sign: hello.manifest hello hello.argv premain-graphene.so
	$(SIGNER) -output hello.manifest.sgx --libpal $(GRAPHENEDIR)/Runtime/libpal-Linux-SGX.so --manifest hello.manifest --key $(GRAPHENEDIR)/Pal/src/host/Linux-SGX/signer/enclave-key.pem
	$(TOKEN) -sig hello.sig -output hello.token


clean:
	rm -f *.sig *.token *.manifest.sgx hello hello.manifest hello.argv uuid


hello: hello.c
	$(CC) -Os -o$@ $<


hello.manifest: hello.manifest.template
	sed -e 's|$$(GRAPHENEDIR)|'"$(GRAPHENEDIR)"'|g' $< > $@


premain-graphene.so:
	wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-graphene.so

hello.argv:
	$(GRAPHENEDIR)/Tools/argv_serializer "Welcome!" "Hello World from Graphene!" > hello.argv

run:
	SGX=1 $(GRAPHENEDIR)/Runtime/pal_loader hello
