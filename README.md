# Signet

[![Build Status](https://img.shields.io/travis/chromakode/signet/master.svg?style=flat-square)](https://travis-ci.org/chromakode/signet)
[![Coverage Status](https://img.shields.io/coveralls/chromakode/signet/master.svg?style=flat-square)](https://coveralls.io/github/chromakode/signet?branch=master)
[![GitHub license](https://img.shields.io/github/license/chromakode/signet.svg?style=flat-square)](https://github.com/chromakode/signet/blob/master/LICENSE)

Signet is a decentralized code signing network. Unlike traditional systems
which focus on authors signing their releases, Signet enables third parties to
publish cryptographically verified statements about software. These statements,
called *attestations*, can be published to public respositories which enable
global lookup and exchange.


## Purpose

Validating the authenticity and security of open source packages is no simple
task. How can we assure that the software we use hasn't been tampered with?
How do we know it functions as expected? To answer these questions, code must
be inspected in a time and labor intensive process. Reviews are typically
carried out on a case-by-case basis by individuals and organizations. The
results of such reviews are rarely published, and there is no standard way to
publish the results of such reviews.

The trustworthiness of the open source ecosystem is a massive shared problem.
For large projects with formal release processes such as the Linux kernel, this
problem is solved via gpg-signed releases. However, the long tail of github-hosted
packages is unsigned. Even if all github users started signing their releases,
this approach wouldn't work because there is no central authority (such as the
official Linux signing key). The peer-to-peer development community needs a
peer-to-peer trust system.

Signet proposes to solve this problem by putting code signing in the hands of
users instead of publishers. By opening this process up to the individuals and
organizations who depend on open source software, participants in development
communities can vouch for each other. Everyone who participates in or uses open
source is a stakeholder in trustworthy ecosystem. Signet's aim is to combine
everyone's knowledge and individual effort into a federated public index.

Building a trust network is a human problem. Even with easily accessible code
signatures, there remains the problem of determining who to trust and how to
verify their identities. Building a large network (and the tooling required to
maintain it) starts with small groups of people. If you're interested in
helping tackle this, check out `sig`, a small utility which facilitates
exchanging code signatures.


## `sig`

:construction: `sig` is an early proof of concept. Please try it out and give
feedback, but proceed with caution! :construction:

The `sig` tool creates, validates, and publishes *attestations*,
[gpg](https://gnupg.org)-signed JSON blobs which annotate files. Sig checks
attestations with your set of trusted public keys to verify that software has
been signed by yourself or trusted third party.

To get started, configure `sig` with your public key:

```sh
$ sig setup B32780D9
Initialized config directory at: /home/demo/.signet/
With public key fingerprint: DFDD705124843F878C6183EBD8C1B99DB32780D9
Welcome to Signet! :)
```

Let's create an attestation about a file we know about:

```sh
$ sig attest ./signet.py
I have reviewed this file (yes/no): yes
It performs as expected and is free of major flaws (yes/no): yes
Comment: My first attestation!
Saved attestation for ./signet.py:
{
  "comment": "My first attestation!",
  "id": "sha256:7c47d79b2e292c509fcdd546ea42427fe3cb02aca40577c1bd8c6f61948c28eb",
  "ok": true,
  "reviewed": true
}
```

Now to verify the same file:

```sh
$ sig verify ./signet.py
identified file as sha256:7c47d79b2e292c509fcdd546ea42427fe3cb02aca40577c1bd8c6f61948c28eb
ok [B32780D9] Dev Test Key <test@demo.com>
file /mnt/shared/signet.py is ok.
```

Your attestations are stored in a *repository* at `~/.signet/repo`. You can
publish this directory on the internet to share it with other people.

Let's fetch another repository:

```sh
$ sig remote add hello-world http://world.com/signet/
$ sig fetch
GET http://world.com/signet/repo.json... done.
GET http://world.com/signet/key.asc... done.
Imported [D9886717] Hello World <hello@world.com>.
```

Now if we verify a file they have signed:

```sh
$ sig verify ./test.txt
identified file as sha256:91751cee0a1ab8414400238a761411daa29643ab4b8243e9a91649e25be53ada
untrusted [D9886717] Hello World <hello@world.com>
file /mnt/shared/signet.py is not verified.
```

We need to mark the new repo's key as trusted before `sig verify` will use its
attestations:

```sh
$ sig trust add B32780D9
Trusted: [D9886717] Hello World <hello@world.com>
```

If we verify the file again, we can see that it is now accepted.

```sh
$ sig verify ./test.txt
identified file as sha256:91751cee0a1ab8414400238a761411daa29643ab4b8243e9a91649e25be53ada
ok [D9886717] Hello World <hello@world.com>
file /mnt/shared/signet.py is ok.
```

A complete listing of available `sig` commands can be viewed via `sig help`.


## Data Formats

### Attestations

An attestation is a signed JSON blob of arbitrary data. It consists of the
following properties:

```js
{
    "data": { ... },
    "key": "full gpg key fingerprint (SHA1)",
    "sig": "base64-encoded gpg signature of json-encoded data property (keys sorted alphabetically)"
}
```

Currently, `sig` records the following data in attestations:

```js
"data": {
    "comment": "My first attestation!",
    "id": "sha256:7c47d79b2e292c509fcdd546ea42427fe3cb02aca40577c1bd8c6f61948c28eb",

    // is this file trustworthy, and does it perform as expected?
    "ok": true,

    // has this file been reviewed by a human?
    "reviewed": true
},
```

### Repositories

A repository stores a mapping of *identifiers* (file content hashes) to
*attestations*. This is wrapped inside its own attestation made by the owner of
the repository. It also contains a version number to aid future format changes.

```js
{
    "data": {
        "attestations": {
            "sha256:7c47d79b2e292c509fcdd546ea42427fe3cb02aca40577c1bd8c6f61948c28eb": [
                {
                    "data": { ... },
                    "key": "...",
                    "sig": "..."
                }
            ],
            "sha256:91751cee0a1ab8414400238a761411daa29643ab4b8243e9a91649e25be53ada": [
                {
                    "data": { ... },
                    "key": "...",
                    "sig": "..."
                }
            ]
        },
        "version": "0.0.1"
    },
    "key": "repo attestation key fingerprint",
    "sig": "repo attestation signature"
}
```


### Future plans

Please the [issues listing](https://github.com/chromakode/signet/issues) for
planned features and open projects.
