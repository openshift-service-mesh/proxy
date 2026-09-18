---
title: "Sequoia-PGP sq"
subtitle: "integration tests, requirements, acceptance criteria"
authors: "The Sequoia-PGP project"
bindings:
- subplot/sq-subplot.yaml
- lib/files.yaml
- lib/runcmd.yaml
impls:
  rust:
  - subplot/sq-subplot.rs
classes:
- json
...

# Introduction

The [Sequoia-PGP][] project is an implementation of the [OpenPGP][]
standard for encryption and digital signatures. Sequoia itself is a
library for the Rust programming language, as well as the `sq` command
line tool for people to use directly. This document captures the
requirements and acceptance criteria for the `sq` tool and how they
are verified, and at the same time acts as an integration test for the
tool.

[Sequoia-PGP]: https://sequoia-pgp.org/
[OpenPGP]: https://en.wikipedia.org/wiki/Pretty_Good_Privacy#OpenPGP


## Testing approach for sq

This document explicitly only covers integration and acceptance
testing of the `sq` command line tool. It does not try to verify that
the underlying library implements OpenPGP correctly: the library has
its own test suite for that. Instead, this document concentrates on
making sure the `sq` command line tool behaves as it should from an
end-user's point of view.

We make the following simplifying assumption: we know the `sq`
developers as competent developers, and assume that they don't
entangle unrelated functionality. By this we mean that we feel we can
assume that the code in `sq` that reads input files is separate from the
code that compresses it, which in turn is independent of the code that
writes output as text or binary data. Thus, we verify each such
functionality independently of each other. This drastically cuts down
the number of feature combinations we need to test. If this assumption
turns out to be incorrect, we will rethink and revise the testing
approach as needed.

We also know, by inspection, that `sq` uses the well-known,
well-respected Rust library `clap` for parsing the command line.
Because of this we feel it's not necessary to verify that, for
example, `sq` notices that a required argument is missing from the
command line, or that it notices that there are extra arguments
present. We will concentrate on testing that when invoked with valid
arguments results in expected output.

## Using Subplot and this document

The acceptance criteria and requirements are explained in prose and
when they can be verified in an automated way, that is done using
_test scenarios_. Both the prose and the scenarios are meant to be
understood and agreed to by all stakeholders in the project.

The [Subplot][] tool is used to render this document into
human-readable form (HTML or PDF), and to generate a test program that
executes the scenarios and checks they all pass.

To achieve this, run the following commands:

~~~sh
$ git clone https://gitlab.com/sequoia-pgp/sequoia-sq.git
$ cd sequoia-sq
$ subplot docgen sq-subplot.md -o sq-subplot.html
$ subplot docgen sq-subplot.md -o sq-subplot.pdf
$ cargo test
~~~

If you only care about generating and running tests, you only need to
run `cargo test`. All the dependencies for that are automatically
handled via `Cargo.toml`.

To generate typeset documents (HTML and PDF), you need the following
software installed:

* [Subplot][], via cargo install or a Debian package (see its website)
* Pandoc
* Parts of TeX Live (for PDF)
* Graphviz

On a Debian system, that means the following packages:

> `subplot pandoc pandoc-citeproc lmodern librsvg2-bin graphviz
> texlive-latex-base texlive-latex-recommended
> texlive-fonts-recommended plantuml`

[Subplot]: https://subplot.liw.fi/


# Smoke test

_Requirement: We must be able to invoke `sq` at all._

This scenario verifies that we can run `sq` in the simplest possible
case: we ask the program for its version. If this works, then we know
that the executable program exists, can be invoked, and at least some
of its command line parsing code works. If this scenario doesn't work,
then we can't expect anything else to work either.

~~~scenario
given an installed sq
when I run sq version
then exit code is 0
then stderr matches regex ^sq \d+\.\d+\.\d+
~~~

# Key management: `sq key`

This chapter covers all key management functionality: the `sq key`
subcommands.

## Key generation: `sq key generate`

This section covers key generation with `sq`. Keys are somewhat
complicated: it is possible to have keys for specify that they can
only used for specific operations, or the time period when they are
valid. Different cryptographic algorithms have different kinds of
keys. We verify these by varying what kind keys we generate and that
they look as expected, when inspected.

### Generate a key with defaults

_Requirement: We must be able to generate new encryption keys and
corresponding certificates._

This scenario generates a new key with `sq` using default settings and
inspects it to see if it looks at least vaguely correct. Note that in
this scenario we don't verify that the key works, other scenarios take
care of that. Here we merely verify that the new key looks OK.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output key.pgp --rev-cert key.pgp.rev
when I run sq inspect key.pgp
then stdout contains "Alice"
then stdout contains "Expiration time: 20"
then stdout contains "Key flags: certification"
then stdout contains "Key flags: signing"
then stdout contains "Key flags: authentication"
then stdout contains "Key flags: transport encryption, data-at-rest encryption"
~~~

### Generate key without user identifiers

_Requirement: We must be able to generate new encryption keys without
any user identifiers._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
then file key.pgp contains "-----BEGIN PGP PRIVATE KEY BLOCK-----"
~~~


### Generate key with more than one user identifier

_Requirement: We must be able to generate new encryption keys with
more than one user identifier._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --userid '<alice@example.com>' --output key.pgp --rev-cert key.pgp.rev
then file key.pgp contains "Comment: Alice"
then file key.pgp contains "Comment: <alice@example.com>"
~~~


### Generate a key for certification only

_Requirement: We must be able to generate a key that can only be used
for certification, and can't be used for signing, encryption or authentication._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cannot-sign --cannot-authenticate --cannot-encrypt
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout doesn't contain "Key flags: signing"
then stdout doesn't contain "Key flags: authentication"
then stdout doesn't contain "Key flags: transport encryption, data-at-rest encryption"
~~~

### Generate a key for encryption only

_Requirement: We must be able to generate a key that can only be used
for encryption, and can't be used for signing or authentication._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cannot-sign --cannot-authenticate
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout doesn't contain "Key flags: signing"
then stdout doesn't contain "Key flags: authentication"
then stdout contains "Key flags: transport encryption, data-at-rest encryption"
~~~

### Generate a key for storage encryption only

_Requirement: We must be able to generate a key that can only be used
for at-rest (storage) encryption._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --can-encrypt=storage
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout doesn't contain "transport encryption"
then stdout contains "Key flags: data-at-rest encryption"
~~~

### Generate a key for transport encryption only

_Requirement: We must be able to generate a key that can only be used
for transport encryption._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --can-encrypt=transport
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: transport encryption"
then stdout doesn't contain "data-at-rest encryption"
~~~

### Generate a key for signing only

_Requirement: We must be able to generate a key that can only be used
for signing, and can't be used for encryption._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cannot-encrypt --cannot-authenticate
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: signing"
then stdout doesn't contain "Key flags: transport encryption, data-at-rest encryption"
then stdout doesn't contain "Key flags: authentication"
~~~


### Generate a key for authentication only

_Requirement: We must be able to generate a key that can only be used
for authentication, and can't be used for encryption or signing._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --can-authenticate --cannot-sign --cannot-encrypt
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: authentication"
then stdout doesn't contain "Key flags: signing"
then stdout doesn't contain "Key flags: transport encryption, data-at-rest encryption"
~~~


### Generate a key for encryption and authentication

_Requirement: We must be able to generate a key that can only be used
for encryption and authentication, and can't be used for signing._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cannot-sign
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: authentication"
then stdout contains "Key flags: transport encryption, data-at-rest encryption"
then stdout doesn't contain "Key flags: signing"
~~~


### Generate a key for encryption and signing

_Requirement: We must be able to generate a key that can only be used
for encryption and signing, and can't be used for authentication._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cannot-authenticate
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: transport encryption, data-at-rest encryption"
then stdout contains "Key flags: signing"
then stdout doesn't contain "Key flags: authentication"
~~~


### Generate a key for signing and authentication

_Requirement: We must be able to generate a key that can only be used
for signing and authentication, and can't be used for encryption._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cannot-encrypt
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout doesn't contain "Key flags: transport encryption, data-at-rest encryption"
then stdout contains "Key flags: signing"
then stdout contains "Key flags: authentication"
~~~



### Generate a key for encryption, authentication and signing

_Requirement: We must be able to generate a key that can be used for
encryption, authentication and signing._

Note that `sq` always creates a key usable for certification.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq inspect key.pgp
then stdout contains "Key flags: certification"
then stdout contains "Key flags: authentication"
then stdout contains "Key flags: transport encryption, data-at-rest encryption"
then stdout contains "Key flags: signing"
~~~



### Generate a version four elliptic curve key

_Requirement: We must be able to generate a v4 Curve25519 key_

This is currently the default key, but we check it separately in case
the default ever changes.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cipher-suite=cv25519 --profile=rfc4880
when I run sq inspect key.pgp
then stdout contains "Public-key algo: EdDSA"
then stdout contains "Public-key size: 256 bits"
~~~

### Generate a version six elliptic curve key

_Requirement: We must be able to generate a v6 Curve25519 key_

This is currently the default key, but we check it separately in case
the default ever changes.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cipher-suite=cv25519 --profile=rfc9580
when I run sq inspect key.pgp
then stdout contains "Public-key algo: Ed25519"
then stdout contains "Public-key size: 256 bits"
~~~

### Generate a three kilobit RSA key

_Requirement: We must be able to generate a 3072-bit RSA key._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cipher-suite=rsa3k
when I run sq inspect key.pgp
then stdout contains "Public-key algo: RSA"
then stdout contains "Public-key size: 3072 bits"
~~~

### Generate four kilobit RSA key

_Requirement: We must be able to generate a 4096-bit RSA key._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --cipher-suite=rsa4k
when I run sq inspect key.pgp
then stdout contains "Public-key algo: RSA"
then stdout contains "Public-key size: 4096 bits"
~~~

### Generate a key with revocation certificate

_Requirement: We must be able to specify where the revocation
certificate is store._

When `sq` generates a key, it also generates a revocation certificate.
By default, this is written to a file next to the key file. However,
we need to able to specify where it goes. This scenario tests various
cases.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
then file key.pgp.rev contains "Comment: Revocation certificate for"

when I run sq key generate --own-key --without-password --no-userids --output key2.pgp --rev-cert rev.pgp
then file rev.pgp contains "Comment: Revocation certificate for"
~~~

### Generate a key with default duration

_Requirement: By default, generated key expire._

We generate a key with defaults, and check the key expires.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq inspect key.pgp
then stdout contains "Expiration time: 20"
~~~

The check for expiration time assumes the scenario is run the 21st
century, and will need to be amended in the 2090s or by time
travellers running it before about the year 2000.

### Generate a key that expires at a given moment

_Requirement: We must be able to generate a key that expires._

Note that the timestamp given to `--expire` is the first second when
the key is no longer valid, not the last second it's valid. The
inspect output is the last second of validity.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --expiration=2038-01-19T03:14:07+00:00
when I run sq inspect key.pgp
then stdout contains "Expiration time: 2038-01-19 03:14"
when I run sq inspect --time 2038-01-20T00:00:00+00:00 key.pgp
then stdout contains "Invalid: The primary key is not live"
~~~

### Generate a key with a given duration

_Requirement: We must be able to generate a key that expires in a
given time._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev --expiration=1y
when I run sq inspect key.pgp
then stdout contains "Expiration time: 20"
~~~

### Generate a key without password

_Requirement: We must be able to generate a that doesn't have a
password._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq inspect key.pgp
then stdout contains "Secret key: Unencrypted"
~~~

### Generate a key with a password

_Requirement: We must be able to generate a that does have a
password._

~~~scenario
given an installed sq
given file password.txt
when I run sq key generate --own-key --no-userids --output key.pgp --rev-cert key.pgp.rev --new-password-file password.txt
when I run sq inspect key.pgp
then stdout contains "Secret key: Encrypted"
~~~

### Update a key by adding User IDs

_Requirement: We must be able to generate a key and add User IDs to it._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key userid add --cert-file key.pgp --name Juliet --email juliet@example.org --output new.pgp
when I run sq inspect new.pgp
then stdout contains "UserID: Juliet"
then stdout contains "UserID: <juliet@example.org>"
~~~


## Certificate extraction: `sq key delete`

This section covers extraction of certificates from keys: the `sq
key delete` subcommand and its variations.


### Extract certificate to the standard output

_Requirement: We must be able to extract a certificate to standard
output._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output -
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~


### Extract certificate to a file

_Requirement: We must be able to extract a certificate to a named
file._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --output key.pgp --rev-cert key.pgp.rev --userid Alice
when I run sq key delete --cert-file key.pgp --output cert.pgp
when I run sq inspect cert.pgp
then stdout contains "OpenPGP Certificate."
then stdout contains "Alice"
~~~


# Keyring management: `sq keyring`

This chapter verifies that the various subcommands to manage keyring
files work: subcommands of the `sq keyring` command.

## Joining keys into a keyring: `sq keyring merge`

The scenarios in this section verify that various ways of joining keys
into a keyring work.

### Join two keys into a textual keyring to stdout

_Requirement: we can join two keys into a keyring, and have it written
to stdout._

This is for secret keys, with the output going to stdout in text form.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring list ring.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### Join two keys into a textual keyring to a named file

_Requirement: we can join two keys into a keyring, and have it written
to a named file._

This is for secret keys, with the output going to a file in text form.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
then file ring.pgp contains "-----BEGIN PGP PRIVATE KEY BLOCK-----"
then file ring.pgp contains "-----END PGP PRIVATE KEY BLOCK-----"
when I run sq inspect ring.pgp
then stdout contains "Transferable Secret Key."
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### Join two keys into a keyring

_Requirement: we can join two keys into a keyring form._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq inspect ring.pgp
then stdout contains "Transferable Secret Key."
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### Join two certificates into a keyring

_Requirement: we can join two certificates into a keyring._

This scenario writes the keyring to a named file. We assume the
writing operation is independent of the types of items in the keyring,
so we don't change writing to stdout separately.

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp
when I run sq keyring merge alice-cert.pgp bob-cert.pgp --output ring.pgp
when I run cat ring.pgp
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
when I run sq inspect ring.pgp
then stdout doesn't contain "Transferable Secret Key."
then stdout contains "OpenPGP Certificate."
then stdout contains "Alice"
then stdout contains "Bob"
~~~


## Filter a keyring: `sq keyring filter`

The scenarios in this section verify that various ways of filtering
the contents of a keyring work: the `sq keyring filter` subcommand
variants.


### We can extract only certificates to named file

_Requirement: we can remove private keys from a keyring, leaving only
certificates._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --to-cert ring.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "OpenPGP Certificate."
then stdout doesn't contain "Transferable Secret Key."
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### We can filter to stdout

_Requirement: we can get filter output to stdout instead of a named
file._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --to-cert ring.pgp
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then stdout contains "-----END PGP PUBLIC KEY BLOCK-----"
~~~

### We can keep only matching certificates

_Requirement: we can remove certificates that don't match filter
criteria._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --userid Bob --output alice.pgp --rev-cert alice.pgp.rev
when I run sq keyring filter --experimental --prune-certs --name Alice alice.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for specific user id

_Requirement: we can extract only keys and certificates with a
specific user id._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --userid Alice ring.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for any of several user ids

_Requirement: we can extract only keys and certificates with any of
specific user ids._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --userid Alice --userid Bob ring.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### We can filter for a name

_Requirement: we can extract only keys and certificates with a name as
part of a user ids._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid 'Alice <alice@example.com>' --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid 'Bob <bob@example.com>' --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --name Alice ring.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for several names

_Requirement: we can extract only keys and certificates with any of
several names as part of the user id._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid 'Alice <alice@example.com>' --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid 'Bob <bob@example.com>' --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --name Alice --name Bob ring.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### We can filter for a domain

_Requirement: we can extract only keys and certificates with a name as
part of a user ids._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid 'Alice <alice@example.com>' --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid 'Bob <bob@sequoia-pgp.org>' --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --domain example.com ring.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### We can filter for several domains

_Requirement: we can extract only keys and certificates with any of
several names as part of the user id._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid 'Alice <alice@example.com>' --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid 'Bob <bob@sequoia-pgp.org>' --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring filter --experimental --domain example.com --domain sequoia-pgp.org ring.pgp --output filtered.pgp
when I run sq inspect filtered.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~


## Listing contents of a keyring: `sq keyring list`

The scenarios in this section verify the contents of a keyring can be listed.

### List keys in a keyring

_Requirement: we can list the keys in a keyring._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring list ring.pgp
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### List keys in a key file

_Requirement: we can list the keys in a key file._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq keyring list alice.pgp
then stdout contains "Alice"
then stdout doesn't contain "Bob"
~~~

### List all user ids in a key file

_Requirement: we can list all user ids._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --userid Bob --output alice.pgp --rev-cert alice.pgp.rev
when I run sq keyring list alice.pgp --all-userids
then stdout contains "Alice"
then stdout contains "Bob"
~~~

### List keys in keyring read from stdin

_Requirement: we can list keys in a keyring that we read from stdin._

This isn't implemented yet, because Subplot needs to add support for
redirecting stdin to come from a file first.



## Split a keyring: `sq keyring split`

The scenarios in this section verify that splitting a keyring into
individual files, one per key: the `sq keyring split` subcommand.

Or rather, there will be such scenarios here when Subplot provides
tools for dealing with randomly named files. Until then, this section
is a placeholder.

~~~
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq keyring merge alice.pgp bob.pgp --output ring.pgp
when I run sq keyring split ring.pgp
then the resulting files match alice,pgp and bob.pgp
~~~

# Encryption and decryption: `sq encrypt` and `sq decrypt`

This chapter has scenarios for verifying that encryption and
decryption work. The overall approach is to do round trips: we
encrypt, then decrypt, and is the result is identical to the input,
all good.

## Encrypt to stdout as ASCII armored

_Requirement: We must be able to encrypt a file using a certificate,
with output going to stdout.

We also verify that the encrypted output doesn't contain the message
in cleartext, just in case.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp
when I run sq encrypt --without-signature --for-file cert.pgp hello.txt
then stdout contains "-----BEGIN PGP MESSAGE-----"
then stdout doesn't contain "hello, world"
~~~


## Encrypt to stdout as binary

_Requirement: We must be able to encrypt a file using a certificate,
with output going to stdout.

We also verify that the encrypted output doesn't contain the message
in cleartext, just in case.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp
when I run sq encrypt --without-signature --binary --for-file cert.pgp hello.txt
then stdout doesn't contain "-----BEGIN PGP MESSAGE-----"
then stdout doesn't contain "hello, world"
~~~


## Encrypt and decrypt using asymmetric encryption

_Requirement: We must be able to encrypt a file using a certificate,
and then decrypt it using the corresponding key._

This scenario creates a plain text file, generates a key, encrypts and
then decrypts the file. The resulting output must be identical to the
original plain text input file. This is a very simplistic scenario and
does not even try to test harder cases (binary files, very large
files, etc).

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp
when I run sq encrypt --without-signature --output x.pgp --for-file cert.pgp hello.txt
when I run sq decrypt --output output.txt --recipient-file key.pgp x.pgp
then files hello.txt and output.txt match
~~~


## Encrypt for multiple recipients

_Requirement: We must be able to encrypt a message for multiple
recipients at a time._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --no-userids --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq encrypt --without-signature --for-file alice-cert.pgp --for-file bob-cert.pgp hello.txt --output x.pgp

when I run sq decrypt --recipient-file alice.pgp --output alice.txt x.pgp
then files hello.txt and alice.txt match

when I run sq decrypt --recipient-file bob.pgp --output bob.txt x.pgp
then files hello.txt and bob.txt match
~~~


## Encrypt and sign at the same time

_Requirement: We must be able to sign and encrypt a message at the
same time._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp

when I run sq encrypt --for-file alice-cert.pgp --signer-file alice.pgp hello.txt --output x.pgp

when I run sq decrypt --recipient-file alice.pgp --output alice.txt x.pgp --signer-file alice-cert.pgp
then files hello.txt and alice.txt match
~~~


## Detect bad signature when decrypting

_Requirement: When decrypting a message, if a signature check fails,
the output file should be deleted.

~~~scenario
given an installed sq
given file hello.txt
given file empty
when I run sq key generate --own-key --without-password --no-userids --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --no-userids --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq encrypt --for-file alice-cert.pgp --signer-file alice.pgp hello.txt --output x.pgp

when I try to run sq decrypt --recipient-file alice.pgp --output alice.txt x.pgp --signer-file bob-cert.pgp
then exit code is 1
then file alice.txt does not exist
~~~




# Certify user identities: `sq pki vouch add`

The scenarios in this chapter verify the certification functionality:
the subcommand `sq certify` in its various variations.

## Certify an identity as ASCII armor

_Requirement: We can certify a user identity on a key._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq inspect bob-cert.pgp
then stdout doesn't contain "Certifications:"

when I run sq pki vouch add --certifier-file alice.pgp --cert-file bob-cert.pgp --userid Bob --output cert.pgp
then file cert.pgp contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
then file cert.pgp contains "-----END PGP PUBLIC KEY BLOCK-----"
when I run sq inspect cert.pgp
then stdout contains "Certifications: 1,"
~~~

## Certify an identity

_Requirement: We can certify a user identity on a key._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq inspect bob-cert.pgp
then stdout doesn't contain "Certifications:"

when I run sq pki vouch add --certifier-file alice.pgp --cert-file bob-cert.pgp --userid Bob --output cert.pgp
when I run sq inspect cert.pgp
then stdout contains "Certifications: 1,"
~~~

## Certify an identity matched by email address

_Requirement: We can certify a user identity on a cert identified by
email address._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid "<alice@example.org>" --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid "<bob@example.org>" --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq pki vouch add --certifier-file alice.pgp --cert-file bob-cert.pgp --email bob@example.org --output cert.pgp
when I run sq inspect cert.pgp
then stdout contains "Certifications: 1,"
~~~

## Certify an identity that is not self-signed

_Requirement: We can certify a user identity on a cert, even if that
user identity doesn't exist on that cert, and consequently has no
self-signature._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq inspect bob-cert.pgp
then stdout doesn't contain "Certifications:"

when I run sq pki vouch add --certifier-file alice.pgp --cert-file bob-cert.pgp --add-userid "My friend Bob" --output cert.pgp
when I run sq inspect cert.pgp
then stdout contains "My friend Bob"
then stdout contains "Certifications: 1,"
~~~

## Certify an email identity that is not self-signed

_Requirement: We can certify an email on a cert, even if that
email address doesn't exist on that cert, and consequently has no
self-signature._

~~~scenario
given an installed sq
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq pki vouch add --certifier-file alice.pgp --cert-file bob-cert.pgp --add-email "bob@example.org" --output cert.pgp
when I run sq inspect cert.pgp
then stdout contains "<bob@example.org>"
then stdout contains "Certifications: 1,"
~~~


# Sign a document and verify the signature: `sq sign` and `sq verify`

This chapter verifies that digital signatures work in `sq`. Like with
encryption, the verification is based on round trips: we create a
signature, and that it matches the signed data. We break this into a
number simple cases.

## Create signature to stdout in ASCII armor

_Requirement: We can create a signature and have it written to
stdout in ASCII armor form._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq sign --message --signer-file key.pgp hello.txt
then stdout contains "-----BEGIN PGP MESSAGE-----"
then stdout contains "-----END PGP MESSAGE-----"
~~~

## Create signature to stdout in binary

_Requirement: We can create a signature and have it written to
stdout in binary form._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq sign --message --signer-file key.pgp --binary hello.txt
then stdout doesn't contain "-----BEGIN PGP MESSAGE-----"
then stdout doesn't contain "-----END PGP MESSAGE-----"
~~~

## Create signature to named file

_Requirement: We can create a signature and have it written to a named
file._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq sign --message --signer-file key.pgp --output signed.pgp hello.txt
then file signed.pgp contains "-----BEGIN PGP MESSAGE-----"
then file signed.pgp contains "-----END PGP MESSAGE-----"
~~~

## Signed file can be verified

_Requirement: We can sign a file and verify the signature._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp
when I run sq sign --message --signer-file key.pgp --output signed.pgp hello.txt
when I run sq verify --message --signer-file cert.pgp signed.pgp
then stdout contains "hello, world"
~~~

## File is signed with all required keys

_Requirement: We can verify that a file is signed by all required
keys._

We verify this by signing a file twice, and verifying there are two
signatures. We also verify that if there is only one signature, it's
not enough, when we need two.

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq sign --message --signer-file alice.pgp --output signed1.pgp hello.txt
when I try to run sq verify --message --signer-file alice-cert.pgp --signer-file bob-cert.pgp --signatures=2 signed1.pgp
then exit code is 1

when I run sq sign --message --append --signer-file bob.pgp --output signed2.pgp signed1.pgp
when I run sq verify --message --signer-file alice-cert.pgp --signer-file bob-cert.pgp --signatures=1 signed2.pgp
then stdout contains "hello, world"
when I run sq verify --message --signer-file alice-cert.pgp --signer-file bob-cert.pgp --signatures=2 signed2.pgp
then stdout contains "hello, world"
~~~

## Signed file cannot be verified if it has been modified

_Requirement: We can sign a file and verifying the signature fails if
the signed file has been modified._

We modify the signed file by removing the third line of it. The file
starts with a line containing "-----BEGIN PGP MESSAGE-----" and then
an empty line, and the third line is actual data. If we delete that,
the file by definition can't be valid anymore.

~~~scenario
given an installed sq
given file hello.txt
given file sed-in-place
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp
when I run sq sign --message --signer-file key.pgp --output signed.pgp hello.txt
when I run sh sed-in-place 3d signed.pgp
when I try to run sq verify --message --signer-file cert.pgp signed.pgp
then command fails
~~~

~~~{#sed-in-place .file .sh}
#!/bin/sh

set -eu
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed "$1" "$2" > "$tmp"
cat "$tmp" > "$2"
~~~

## Create cleartext signature

_Requirement: We can create a signature such that the signed data is
included in a readable form._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp

when I run sq sign --cleartext --signer-file key.pgp --output signed.txt hello.txt
then file signed.txt contains "-----BEGIN PGP SIGNED MESSAGE-----"
then file signed.txt contains "hello, world"
then file signed.txt contains "-----END PGP SIGNATURE-----"
when I run sq verify --cleartext --signer-file cert.pgp signed.txt
then stdout contains "hello, world"
~~~


## Cleartext signature cannot be verified if it has been modified

_Requirement: If a cleartext signature is modified, it can't be
verified._

~~~scenario
given an installed sq
given file hello.txt
given file sed-in-place
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp

when I run sq sign --cleartext --signer-file key.pgp --output signed.txt hello.txt
when I run sh sed-in-place s/hello/HELLO/ signed.txt
when I try to run sq verify --cleartext --signer-file cert.pgp signed.txt
then exit code is 1
~~~

## Create a detached signature

_Requirement: We can create a signature that is doesn't include the
data it signs._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp

when I run sq sign --signature-file=hello.txt.sig --signer-file key.pgp hello.txt
then file hello.txt.sig contains "-----BEGIN PGP SIGNATURE-----"
then file hello.txt.sig contains "-----END PGP SIGNATURE-----"
when I run sq verify --signature-file=hello.txt.sig --signer-file=cert.pgp hello.txt
then stdout doesn't contain "hello, world"
then exit code is 0
~~~


## Detached signature cannot be verified if the data has been modified

_Requirement: If the file that is signed using a detached signature is
modified, the signature can't be verified._

~~~scenario
given an installed sq
given file hello.txt
given file sed-in-place
when I run sq key generate --own-key --without-password --no-userids --output key.pgp --rev-cert key.pgp.rev
when I run sq key delete --cert-file key.pgp --output cert.pgp

when I run sq sign --signature-file=hello.txt.sig --signer-file key.pgp hello.txt
when I run sh sed-in-place s/hello/HELLO/ hello.txt
when I try to run sq verify --signature-file=hello.txt.sig --signer-file=cert.pgp hello.txt
then exit code is 1
~~~


## Append signature to already signed message

_Requirement: We must be able to add a signature to an already signed
message._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq sign --message --signer-file alice.pgp --output signed1.pgp hello.txt
when I run sq sign --message --append --signer-file bob.pgp --output signed2.pgp signed1.pgp
when I run sq verify --message signed2.pgp --signer-file alice-cert.pgp --signer-file bob-cert.pgp
then stdout contains "hello, world"
then stderr matches regex 2.authenticated signatures
~~~

## Merge signed files

_Requirement: We must be able to merge signatures of a file signed
twice separately._

~~~scenario
given an installed sq
given file hello.txt
when I run sq key generate --own-key --without-password --userid Alice --output alice.pgp --rev-cert alice.pgp.rev
when I run sq key delete --cert-file alice.pgp --output alice-cert.pgp
when I run sq key generate --own-key --without-password --userid Bob --output bob.pgp --rev-cert bob.pgp.rev
when I run sq key delete --cert-file bob.pgp --output bob-cert.pgp

when I run sq sign --message --signer-file alice.pgp --output signed1.pgp hello.txt
when I run sq sign --message --signer-file bob.pgp --output signed2.pgp hello.txt
when I run sq sign --message --output merged.pgp --merge=signed2.pgp signed1.pgp
when I run sq verify --message --signer-file alice-cert.pgp --signer-file bob-cert.pgp merged.pgp
then stdout contains "hello, world"
then stderr matches regex 2.authenticated signatures
~~~




# ASCII Armor data representation: `sq packet armor` and `sq packet dearmor`

The scenarios in this chapter verify that `sq` can convert data into
the "ASCII Armor" representation and back.

## Convert data file to armored format to stdout

_Requirement: We must be able to convert a file to armored format to
stdout._

~~~scenario
given an installed sq
given file hello.txt
when I run sq packet armor hello.txt
then stdout contains "-----BEGIN PGP ARMORED FILE-----"
then stdout contains "-----END PGP ARMORED FILE-----"
~~~

## Convert data file to armored format to file

_Requirement: We must be able to convert a file to armored format to a
named file._

~~~scenario
given an installed sq
given file hello.txt
given file hello.asc
when I run sq packet armor hello.txt --output hello.out
then files hello.asc and hello.out match
~~~


## Convert data file to armored format with desired label

_Requirement: We must be able to convert a file to armored format with
the label we choose._

~~~scenario
given an installed sq
given file hello.txt
when I run sq packet armor hello.txt --label auto
then stdout contains "-----BEGIN PGP ARMORED FILE-----"
when I run sq packet armor hello.txt --label message
then stdout contains "-----BEGIN PGP MESSAGE-----"
when I run sq packet armor hello.txt --label cert
then stdout contains "-----BEGIN PGP PUBLIC KEY BLOCK-----"
when I run sq packet armor hello.txt --label key
then stdout contains "-----BEGIN PGP PRIVATE KEY BLOCK-----"
when I run sq packet armor hello.txt --label sig
then stdout contains "-----BEGIN PGP SIGNATURE-----"
when I run sq packet armor hello.txt --label file
then stdout contains "-----BEGIN PGP ARMORED FILE-----"
~~~

## Convert data file from armored format to stdout

_Requirement: We must be able to convert a file from armored format to
stdout._

~~~scenario
given an installed sq
given file hello.asc
when I run sq packet dearmor hello.asc
then stdout contains "hello, world"
~~~

## Convert data file from armored format to file

_Requirement: We must be able to convert a file from armored format to
a named file._

~~~scenario
given an installed sq
given file hello.txt
given file hello.asc
when I run sq packet dearmor hello.asc --output hello.out
then files hello.txt and hello.out match
~~~

## Armor round trip

_Requirement: We must be able to convert data to armored format and
back._

~~~scenario
given an installed sq
given file hello.txt
when I run sq packet armor hello.txt --output hello.tmp
when I run sq packet dearmor hello.tmp --output hello.out
then files hello.txt and hello.out match
~~~



# Web key directory (WKD) support

[Web Key Directory]: https://wiki.gnupg.org/WKD
[Internet Draft 14 for WKD]: https://www.ietf.org/archive/id/draft-koch-openpgp-webkey-service-14.html

[Web Key Directory][] (WKD) specifies how to locate a certificate for
a given email address by constructing HTTPS URLs from the email
address. It is specified in [Internet Draft 14 for WKD][].


# Test data file

We use this file as an input file in the tests. It is a very short
file, and a text file, but this is enough for the current set of
requirements and scenarios.

~~~{#hello.txt .file}
hello, world
~~~

This is the same content, but in ASCII armored representation.

~~~{#hello.asc .file}
-----BEGIN PGP ARMORED FILE-----

aGVsbG8sIHdvcmxkCg==
=FOuc
-----END PGP ARMORED FILE-----
~~~

This is an empty file.

~~~{#empty .file add-newline=no}
~~~

This is a file containing a password.

~~~{#password.txt .file}
hunter2
~~~
