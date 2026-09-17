# Introduction

This directory contains data for the examples.

The test suite executes each subcommand's examples.  Each subcommand
has its own context (temporary directory), which is set to the current
working directory.  The contents of this directory are copied into
that directory.  If a subcommand has multiple examples, they are
execute after each other in the same context.

By using static data, we can use known fingerprints in the examples.

# Contents

- alice-secret.pgp: A general-purpose key for Alice
  <alice@example.org>.

    - Imported into the cert store.
    - NOT Imported into the key store.

- alice-new-secret.pgp: A general-purpose key for Alice
  <alice@example.org>.

    - Not related to alice-secret.pgp, modulo having the same user ID.
    - NOT imported into the cert store.
    - NOT Imported into the key store.

- bob.pgp: A general-purpose certificate for Bob
  <bob@example.org>.

    - Imported into the cert store.
    - Certified by Alice.

- bob-secret.pgp: A general-purpose key for Bob
  <bob@example.org>.

    - NOT Imported into the key store.

- juliet.pgp: A general-purpose certificate for Juliet Capulet
  <juliet@example.org>.

    - NOT imported into the cert store.

- juliet-secret.pgp: A general-purpose key for Juliet Capulet
  <juliet@example.org>.

    - NOT imported into the key store.

- romeo.pgp: A general-purpose certificate for Romeo Montague
  <romeo@example.org>.

    - NOT imported into the cert store.

- romeo-secret.pgp: A general-purpose key for Romeo Montague
  <romeo@example.org>.

    - NOT imported into the key store.

- ca-secret.pgp: A key with the user ID <ca@example.org>.

    - NOT imported into the cert store.

- bare.pgp: A bare key.

  A bare key is a public key without any components or signatures.
  Bare keys are useful when working with raw keys, e.g., keys
  generated on an OpenPGP card, a TPM device, etc.  To add them to a
  certificate, they just need to be wrapped in a minimal amount of
  OpenPGP framing; no signatures are required.

    - NOT imported into the key store.

- document.txt, document.sig: A document, and a detached signatured.

    - `sq sign --detached --signer-file juliet-secret.pgp document.txt > document.sig`
    - `sq verify --signer-file juliet-secret.pgp --detached document.sig document.txt`

- document.pgp: An inline-signed document, equivalent to the above.

- message.pgp: A document encrypted for Bob, and signed by Alice.

    - `echo 'Golf this afternoon?' | sq encrypt --for-file bob-secret.pgp --signer-file alice-secret.pgp > message.pgp`

- ciphertext.pgp: A document encrypted for Juliet, and signed by Romeo.

    - `echo 'Ti amo!' | sq encrypt --for-file juliet.pgp --signer-file romeo-secret.pgp > ciphertext.pgp`

- debian/: The checksum file, the signature file, and the signing key
  for the debian 12.7.0 release.

  - https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA512SUMS
  - https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA512SUMS.sign
