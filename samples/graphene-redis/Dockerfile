# syntax=docker/dockerfile:experimental

FROM alpine/git:latest AS pull
RUN git clone https://github.com/edgelesssys/marblerun.git /premain

FROM ghcr.io/edgelesssys/edgelessrt-dev AS build-premain
COPY --from=pull /premain /premain
WORKDIR /premain/build
RUN cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
RUN make premain-graphene

FROM ghcr.io/edgelesssys/edgelessrt-deploy:latest AS release
RUN apt-get update && apt-get install -y git meson build-essential autoconf gawk bison wget python3 libcurl4-openssl-dev \
    python3-protobuf libprotobuf-c-dev protobuf-c-compiler python3-pip software-properties-common python3-click python3-jinja2
RUN wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add
RUN add-apt-repository 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main'
RUN apt-get install -y libsgx-quote-ex-dev libsgx-aesm-launch-plugin
RUN python3 -m pip install "toml>=0.10"

RUN git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git /SGXDriver
WORKDIR /SGXDriver
RUN git reset --hard a93785f7d66527aa3bd331ba77b7993f3f9c729b



RUN git clone https://github.com/oscarlab/graphene.git /graphene
WORKDIR /graphene
RUN git reset --hard b37ac75efec0c1183fd42340ce2d3e04dcfb3388
RUN make ISGX_DRIVER_PATH=/SGXDriver/driver/linux/ SGX=1
RUN meson build -Ddirect=disabled -Dsgx=enabled
RUN ninja -C build
RUN ninja -C build install

COPY --from=build-premain /premain/build/premain-graphene /graphene/Examples/redis/
COPY redis-server.manifest.template /graphene/Examples/redis/
WORKDIR /graphene/Examples/redis
ENV BUILD_TLS yes
RUN --mount=type=secret,id=signingkey,dst=/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem,required=true \
    make clean && make SGX=1
ENTRYPOINT ["graphene-sgx", "/graphene/Examples/redis/redis-server" ]
