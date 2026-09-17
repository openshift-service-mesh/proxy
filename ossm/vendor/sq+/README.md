# sq, the Sequoia-PGP command line tool

[Sequoia-PGP][] is an implementation of OpenPGP in Rust. It includes a
suite of library crates, which are meant to be used from applications.
This crate provides the `sq` command line application. `sq` is aimed
at command line users as a way to use OpenPGP conveniently from the
command line.

See the [sq user documentation][] for instructions. The program also has built-in
help, using the `--help` option and `help` subcommand:

~~~sh
$ sq help
...
~~~

You can also browse the [manual pages][], look at our [acceptance
criteria][], and browse the [rustdoc output][] if you want to learn about
the implementation.

[Sequoia-PGP]: https://sequoia-pgp.org/
[sq user documentation]: https://sequoia-pgp.gitlab.io/user-documentation
[manual pages]: https://sequoia-pgp.gitlab.io/sequoia-sq/man/
[acceptance criteria]: https://sequoia-pgp.gitlab.io/sequoia-sq/subplot/
[rustdoc output]: https://sequoia-pgp.gitlab.io/sequoia-sq/impl/

## Installing

The `sq` tool can be installed using cargo:

```sh
cargo install sequoia-sq
```

Please see [sequoia-openpgp's README] for how to install build
dependencies on your system.

[sequoia-openpgp's README]: https://gitlab.com/sequoia-pgp/sequoia#requirements-and-msrv

## Building from source

This crate can be built from a source checkout using the standard
`cargo` toolchain:

```sh
cargo build
```

The above creates the `sq` executable, the manual pages, and its shell
completions.  By default, the manual pages and shell completions are
put into the `cargo` target directory, but the exact location is
unpredictable.  To write the assets to a predictable location, set the
environment variable `ASSET_OUT_DIR` to a suitable location.

## Using a Container (Docker, Podman, etc.)

The command line tool `sq` can also be built using an OCI compatible image
builder, eg. podman or docker:

```shell
$ podman build -f Containerfile -t sq .
$ podman run --rm -i sq --help
```

You can then use sq in the container.

For example searching for a certificate:

```shell
$ podman run --rm -i sq network search 653909A2F0E37C106F5FAF546C8857E0D8E8F074
```

All sq state is stored under `/sequoia` inside of the container, thus if you
would like to persist the state between container runs you may bind mount the
directory on the host.

```shell
$ mkdir sq-container # create a directory on the host where you will mount the working dir from the container
$ podman run --rm -i -v $PWD/sq-container:/sequoia sq network search 653909A2F0E37C106F5FAF546C8857E0D8E8F074
$ podman run --rm -i -v $PWD/sq-container:/sequoia sq inspect --cert 653909A2F0E37C106F5FAF546C8857E0D8E8F074

```

The container environment has sq manpages and bash completion configured. By
default the container will run sq as its "entrypoint", so if you would like
to be dropped into a shell then override the entrypoint as follows.

```shell
# Note the "-t"; Necessary for the allocation of a pseudo-TTY.
$ podman run --rm -t -i --entrypoint bash sq
```

A current build of the container image is available from the gitlab registry.
Rename it to `sq` locally so that it matches the above commands and for convenience.

```shell
$ podman pull registry.gitlab.com/sequoia-pgp/sequoia-sq:latest
$ podman tag registry.gitlab.com/sequoia-pgp/sequoia-sq:latest sq
$ podman run --rm -i sq --help
```
