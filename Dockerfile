FROM --platform=linux/amd64 ubuntu:jammy

RUN export DEBIAN_FRONTEND=noninteractive \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
  python3-pip \
  gcc \
  git \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m slither
USER slither

WORKDIR /home/slither
RUN mkdir mnt
RUN git clone --depth 1 https://github.com/crytic/slither.git
WORKDIR /home/slither/slither

RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 wheel -w ./wheels . solc-select pip setuptools wheel xlsxwriter

COPY --chown=slither:slither inspex-plugins/ plugin_example/

ENV PATH="/home/slither/.local/bin:${PATH}"

RUN pip3 install --user --no-cache-dir --upgrade --no-index --no-deps ./wheels/*.whl

RUN cd plugin_example; \
    python3 setup.py develop --install-dir /home/slither/.local/lib/python3.10/site-packages; exit 0

WORKDIR /home/slither

CMD /bin/bash