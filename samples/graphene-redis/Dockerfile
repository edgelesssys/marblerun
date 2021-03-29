# syntax=docker/dockerfile:experimental

FROM alpine/git:latest AS pull
git clone https://github.com/edgelesssys/marblerun.git /premain

FROM ghcr.io/edgelesssys/edgelessrt-dev AS build-premain
COPY --from=pull /premain /premain
WORKDIR /premain/build
RUN cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
RUN make premain-graphene

# Use with fully built graphene as build context
# Place redis-server.manifest.template from this repo inside $GRAPHENE_DIR/Examples/redis/
FROM ghcr.io/edgelesssys/edgelessrt-deploy:latest AS release
RUN apt-get update && apt-get install -y build-essential autoconf gawk bison wget python3 libcurl4-openssl-dev \
    python3-protobuf libprotobuf-c-dev protobuf-c-compiler python3-pip software-properties-common
RUN wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add
RUN add-apt-repository 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main'
RUN apt-get install -y libsgx-quote-ex-dev libsgx-aesm-launch-plugin
RUN python3 -m pip install toml
COPY . /graphene
COPY --from=build-premain /premain/build/premain-graphene /graphene/Examples/redis
WORKDIR /graphene/Examples/redis
RUN make clean && make SGX=1
ENTRYPOINT [ "bash", "-c", "SGX=1 /graphene/Runtime/pal_loader /graphene/Examples/redis/redis-server" ]
