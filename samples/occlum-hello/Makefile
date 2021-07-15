SHELL := /bin/bash
all: build
.PHONY: clean all

clean:
	rm -rf occlum-instance hello premain-libos

build: occlum-instance hello premain-libos
	cp premain-libos occlum-instance/image/bin/premain-libos
	cp hello occlum-instance/image/bin/hello
	cd occlum-instance; occlum build

occlum-instance:
	occlum new occlum-instance
	cp Occlum.json ./occlum-instance/Occlum.json
	# Get DNS resolution working. Adjust this if you want to use another DNS resolver.
	echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > ./occlum-instance/image/etc/resolv.conf
	echo -e "hosts:	files dns" > ./occlum-instance/image/etc/nsswitch.conf
	cp /opt/occlum/glibc/lib/libnss_dns.so.2 /opt/occlum/glibc/lib/libnss_files.so.2 /opt/occlum/glibc/lib/libresolv.so.2 occlum-instance/image/opt/occlum/glibc/lib/

hello: hello.c
	occlum-gcc -Os -o$@ $<

premain-libos:
	wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-libos
	chmod +x premain-libos

run:
	cd occlum-instance; occlum run /bin/premain-libos
