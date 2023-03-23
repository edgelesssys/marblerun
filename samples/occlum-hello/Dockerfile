# Replace standard Intel DCAP plugin with Azure DCAP plugin
FROM occlum/occlum:0.29.3-ubuntu20.04

ARG GO_VER=1.20.2
RUN echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main" | sudo tee /etc/apt/sources.list.d/msprod.list && \
    wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add - && \
    sudo apt-get update && \
    sudo apt-get -y install az-dcap-client && \
    sudo apt remove -y golang-go && \
    rm -rf /usr/local/go && \
    wget https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VER}.linux-amd64.tar.gz && \
    rm go${GO_VER}.linux-amd64.tar.gz && \
    cp /usr/lib/libdcap_quoteprov.so /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.azure && \
    ln -sf /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.azure /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1
ENV PATH ${PATH}:/usr/local/go/bin
