SHELL := /bin/bash
all: build
.PHONY: clean all

clean:
	rm -rf occlum-instance hello premain-occlum

build: occlum-instance hello premain-occlum
	cp premain-occlum occlum-instance/image/bin/premain-occlum
	cp hello occlum-instance/image/bin/hello
	cd occlum-instance; occlum build

occlum-instance:
	occlum new occlum-instance
	cp Occlum.json ./occlum-instance/Occlum.json
	# Get external DNS resolution working. Adjust this if you want to use another DNS resolver.
	echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > ./occlum-instance/image/etc/resolv.conf

hello: hello.c
	occlum-gcc -Os -o$@ $<

premain-occlum:
	occlum-go build -o premain-occlum ../../cmd/premain-occlum

run:
	cd occlum-instance; occlum run /bin/premain-occlum
