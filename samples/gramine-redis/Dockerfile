FROM alpine/git:latest AS pull_marblerun
RUN git clone --depth=1 https://github.com/edgelesssys/marblerun.git /marblerun

FROM alpine/git:latest AS pull_gramine
RUN git clone --depth=1 --branch v1.4 https://github.com/gramineproject/gramine /gramine

FROM ghcr.io/edgelesssys/edgelessrt-dev:latest AS build-premain
COPY --from=pull_marblerun /marblerun /premain
WORKDIR /premain/build
RUN cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
RUN make premain-libos

FROM gramineproject/gramine:v1.4 AS release

RUN apt-get update && apt-get install -y \
    wget \
    libssl-dev \
    libsgx-quote-ex-dev \
    libsgx-dcap-default-qpl \
    build-essential \
    libprotobuf-c-dev \
    && apt-get clean -y && apt-get autoclean -y && apt-get autoremove -y

COPY --from=pull_gramine /gramine /gramine
COPY --from=build-premain /premain/build/premain-libos /gramine/CI-Examples/redis/
COPY ./redis-server.manifest.template ./start.sh /gramine/CI-Examples/redis/
WORKDIR /gramine/CI-Examples/redis/
ENV BUILD_TLS yes
RUN --mount=type=secret,id=signingkey,dst=/root/.config/gramine/enclave-key.pem,required=true \
    make clean && make SGX=1
ENTRYPOINT [ "/gramine/CI-Examples/redis/start.sh" ]
