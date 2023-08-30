FROM occlum/occlum:0.29.7-ubuntu20.04

ARG ERT_VERSION="0.4.1"
ARG ERT_DEB=edgelessrt_${ERT_VERSION}_amd64_ubuntu-20.04.deb
RUN wget https://github.com/edgelesssys/edgelessrt/releases/download/v${ERT_VERSION}/$ERT_DEB && \
    sudo apt install -y ./$ERT_DEB build-essential
ENV PATH=/opt/edgelessrt/bin:$PATH
