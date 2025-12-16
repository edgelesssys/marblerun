FROM ghcr.io/edgelesssys/edgelessrt-deploy:latest AS release
COPY ./dockerfiles/start.sh ./coordinator-enclave.signed ./libsymcrypt.so.103 /
ENV PATH=${PATH}:/opt/edgelessrt/bin
ENTRYPOINT [ "/start.sh" ]
