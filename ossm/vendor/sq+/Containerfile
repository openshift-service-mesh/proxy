# See https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/README.md#debian
# for system requirements
FROM docker.io/library/debian:trixie AS build

# create a sandbox user for the build (in ~builder) and install (in /opt)
# give it permissions to the build dir and home
# upgrade everything
# add dependencies, as specified by the Sequoia README.md file
RUN groupadd builder && \
    useradd --no-log-init --create-home --gid builder builder && \
    apt-get update && \
    apt-get upgrade --assume-yes && \
    apt-get install --assume-yes --no-install-recommends \
        ca-certificates \
        capnproto \
        cargo \
        git \
        libclang-dev \
        libsqlite3-dev \
        libssl-dev \
        make \
        nettle-dev \
        pkg-config \
        rustc \
        && \
    apt-get clean && \
    chown builder /opt

COPY --chown=builder:builder . /home/builder/sequoia

# switch to the sandbox user
USER builder

# retry build because cargo sometimes segfaults during download (#918854)
#
# the `build-release` target is used instead of the default because
# `install` calls it after anyways
RUN cd /home/builder/sequoia && \
    CARGO_TARGET_DIR=/tmp/target ASSET_OUT_DIR=/tmp/target/assets cargo build -p sequoia-sq --release && \
    install --strip -D --target-directory /opt/usr/local/bin \
                  /tmp/target/release/sq

FROM docker.io/library/debian:trixie-slim AS sq-base

RUN apt-get update && \
    apt-get upgrade --assume-yes && \
    apt-get install -yqq \
            bash-completion \
            ca-certificates \
	    libssl3 \
	    libsqlite3-0 \
	    man-db && \
    apt-get clean && \
    rm -fr -- /var/lib/apt/lists/* /var/cache/*

FROM sq-base AS sq

COPY --from=build /opt/usr/local/bin/sq /usr/local/bin/sq
COPY --from=build /etc/ssl/certs /etc/ssl/certs
COPY --from=build /tmp/target/assets/shell-completions/sq.bash /etc/bash_completion.d/sq
COPY --from=build /tmp/target/assets/man-pages/* /usr/share/man/man1/

ENV SEQUOIA_HOME=/sequoia SEQUOIA_CERT_STORE=/sequoia/certstore SEQUOIA_KEY_STORE=/sequoia/keystore

# Set the default workdir to sequoia home directory
WORKDIR /sequoia

VOLUME /sequoia
ENTRYPOINT ["/usr/local/bin/sq"]
