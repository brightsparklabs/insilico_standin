# Insilico Stand-in

[![Build Status](https://travis-ci.org/brightsparklabs/insilico_standin.svg?branch=master)](https://travis-ci.org/brightsparklabs/insilico_standin)

A stand-in library for Insilico to test the behaviour of Asanti. This will
eventually be integrated into Insilico directly. In the interim it is used to help us understand the API and performance requirements of Asanti.

## Setup and Build

```bash
git clone git@github.com:brightsparklabs/insilico_standin.git
cd insilico_standin
gradle assemble
```

## Licenses

Refer to the LICENSE file for details.

This project makes use of the following libraries:

- [Asanti](https://github.com/brightsparklabs/asanti)
- [Google Guava](https://github.com/google/guava)
- [Bouncy Castle Crypto APIs](http://www.bouncycastle.org/)
