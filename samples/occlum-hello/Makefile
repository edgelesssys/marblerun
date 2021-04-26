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

hello: hello.c
	occlum-gcc -Os -o$@ $<

premain-occlum:
	occlum-go build -o premain-occlum ../../cmd/premain-occlum

run:
	cd occlum-instance; occlum run /bin/premain-occlum
