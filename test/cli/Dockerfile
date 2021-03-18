FROM alpine/git:latest AS pull
RUN git clone https://github.com/edgelesssys/marblerun.git /hello-marble
WORKDIR /marble-injector

FROM ghcr.io/edgelesssys/ego-dev:latest AS build
COPY --from=pull /hello-marble /hello-marble
WORKDIR /hello-marble/samples/helloworld
RUN ego-go build
RUN ego sign helloworld

FROM ghcr.io/edgelesssys/ego-deploy:latest AS release
LABEL description="HelloMarble"
COPY --from=build /hello-marble/samples/helloworld /
ENTRYPOINT [ "ego", "marblerun", "/helloworld" ]
