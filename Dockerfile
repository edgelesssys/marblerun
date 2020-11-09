# syntax=docker/dockerfile:experimental

FROM alpine/git:latest AS pull
RUN --mount=type=secret,id=repoaccess,dst=/root/.netrc,required=true git clone https://github.com/edgelesssys/coordinator.git /coordinator

FROM ghcr.io/edgelesssys/edgelessrt:latest AS build
COPY --from=pull /coordinator /coordinator
WORKDIR /coordinator/build
RUN cmake ..
RUN --mount=type=secret,id=signingkey,dst=/coordinator/build/private.pem,required=true make

FROM ghcr.io/edgelesssys/edgelessrt:deploy AS release
LABEL description="EdgelessCoordinator"
COPY --from=build /coordinator/build/coordinator-enclave.signed /coordinator/build/coordinator-noenclave /
ENTRYPOINT ["erthost", "coordinator-enclave.signed"]
