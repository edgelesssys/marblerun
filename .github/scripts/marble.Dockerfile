FROM ghcr.io/edgelesssys/edgelessrt-deploy:latest AS release
COPY ./marble-test-enclave.signed /
ENV PATH=${PATH}:/opt/edgelessrt/bin
ENTRYPOINT [ "erthost", "/marble-test-enclave.signed" ]
