# syntax=docker/dockerfile:experimental

FROM alpine/git:latest AS pull_marblerun
RUN git clone https://github.com/edgelesssys/marblerun.git /marblerun

FROM alpine/git:latest AS pull_gramine
RUN git clone --branch v1.3.1 https://github.com/gramineproject/gramine /gramine

FROM ghcr.io/edgelesssys/edgelessrt-dev AS build-premain
COPY --from=pull_marblerun /marblerun /premain
WORKDIR /premain/build
RUN cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
RUN make premain-libos

FROM ubuntu:20.04
RUN apt update && \
    apt install -y libssl-dev gnupg software-properties-common

RUN apt-key adv --fetch-keys https://packages.microsoft.com/keys/microsoft.asc && \
    apt-add-repository 'https://packages.microsoft.com/ubuntu/20.04/prod main' && \
    apt-key adv --fetch-keys https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    add-apt-repository 'https://download.01.org/intel-sgx/sgx_repo/ubuntu main' && \
    apt-key adv --fetch-keys https://packages.gramineproject.io/gramine-keyring.gpg && \
    apt-add-repository 'deb [arch=amd64] https://packages.gramineproject.io/ focal main'

RUN apt-get update && apt-get install -y \
    az-dcap-client \
    wget \
    libsgx-quote-ex-dev \
    libsgx-aesm-launch-plugin \
    build-essential \
    libprotobuf-c-dev \
    gramine && \
    apt-get clean -y && apt-get autoclean -y && apt-get autoremove -y

COPY --from=pull_gramine /gramine /gramine
COPY --from=build-premain /premain/build/premain-libos /gramine/CI-Examples/redis/
COPY ./redis-server.manifest.template /gramine/CI-Examples/redis/
WORKDIR /gramine/CI-Examples/redis/
ENV BUILD_TLS yes
RUN --mount=type=secret,id=signingkey,dst=/root/.config/gramine/enclave-key.pem,required=true \
    make clean && make SGX=1
ENTRYPOINT ["gramine-sgx", "/gramine/CI-Examples/redis/redis-server" ]
