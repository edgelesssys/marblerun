FROM ghcr.io/edgelesssys/edgelessrt-deploy:latest AS release
COPY ./dockerfiles/start.sh /
COPY ./coordinator-enclave.signed /
ENV PATH=${PATH}:/opt/edgelessrt/bin
ENTRYPOINT [ "/start.sh" ]
