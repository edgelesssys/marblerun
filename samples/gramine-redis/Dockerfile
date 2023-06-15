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
RUN curl -fsSLo /usr/share/keyrings/microsoft.asc https://packages.microsoft.com/keys/microsoft.asc && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.asc] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | \
    tee /etc/apt/sources.list.d/msprod.list

RUN apt-get update && apt-get install -y \
    az-dcap-client \
    wget \
    libssl-dev \
    libsgx-quote-ex-dev \
    build-essential \
    libprotobuf-c-dev \
    && apt-get clean -y && apt-get autoclean -y && apt-get autoremove -y

COPY --from=pull_gramine /gramine /gramine
COPY --from=build-premain /premain/build/premain-libos /gramine/CI-Examples/redis/
COPY ./redis-server.manifest.template /gramine/CI-Examples/redis/
WORKDIR /gramine/CI-Examples/redis/
ENV BUILD_TLS yes
RUN --mount=type=secret,id=signingkey,dst=/root/.config/gramine/enclave-key.pem,required=true \
    make clean && make SGX=1
ENTRYPOINT ["gramine-sgx", "/gramine/CI-Examples/redis/redis-server" ]
