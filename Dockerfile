FROM --platform=linux/amd64 ubuntu:jammy

RUN export DEBIAN_FRONTEND=noninteractive \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
  python3-pip \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m slither
USER slither

WORKDIR /home/slither
RUN mkdir mnt
RUN mkdir inspex-plugins

RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir solc-select xlsxwriter

COPY --chown=slither:slither inspex-plugins/ inspex-plugins/

ENV PATH="/home/slither/.local/bin:${PATH}"

RUN pip3 install slither-analyzer

RUN cd inspex-plugins; \
    python3 setup.py develop --install-dir /home/slither/.local/lib/python3.10/site-packages; exit 0

WORKDIR /home/slither

RUN solc-select install 0.8.17; solc-select use 0.8.17;

CMD /bin/bash