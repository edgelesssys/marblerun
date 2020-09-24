# syntax=docker/dockerfile:experimental

FROM ubuntu:18.04 AS pull
RUN apt update && \
    apt install -y git
RUN ln -s /run/secrets/repoaccess ~/.netrc
RUN --mount=type=secret,id=repoaccess git clone https://github.com/edgelesssys/coordinator.git

FROM ghcr.io/edgelesssys/edgelessrt-private:latest AS build
COPY --from=pull /coordinator /coordinator
WORKDIR /coordinator/build
RUN cmake .. && make

FROM ghcr.io/edgelesssys/edgelessrt-private:deploy AS release
LABEL description="EdgelessCoordinator"
ENV MESHPORT=25556
EXPOSE 80/tcp
EXPOSE ${MESHPORT}/tcp
COPY --from=build /coordinator/build/coordinator /coordinator/build/coordinator-noenclave /coordinator/build/enclave.signed /
ENTRYPOINT /coordinator-noenclave -ip=localhost:${MESHPORT} -ep=localhost:80
