# Minimal TLS
[Tianyi Jin](https://github.com/FreddieJin), [Cyrus Malekpour](https://github.com/cmalekpour), [Bhuvanesh Murali](https://github.com/bhuvanesh8), [Daniel Saha](https://github.com/drs5ma)

#### Problem
In recent years, TLS implementations have been targeted with memory corruption or leakage issues, which they are vulnerable. Since they are implemented in C/C++, it is difficult to make these implementations resistant to such attacks. Many implementations also attempt to include a wide variety of cipher suites, which may improve client suport but drastically increases the amount of crypto code that needs to be audited and written.

#### Goal
We plan to create a "minimal" implementation of TLS 1.3 with the goal of 95% support of browser clients (including beta/nightly versions). To accomplish this, we will identify the least possible set of server features and cipher suites we can support to meet this goal, with a strong focus on security. We will implement only a few key TLS extensions (ex: SNI, OCSP) with fail-safes for other features. We will not enable the 0-RTT mode, which is vulnerable to replay attacks. We also explicitly support only the ChaCha20-Poly1305 ciphersuite by default, since it provides good performance without risk of timing attack.

The project will be written in the Rust programming language to provide good performance while removing the risk of memory corruption attacks. We will develop a library that exposes a simple API, similar to [libressl's libtls](http://man.openbsd.org/tls_init). After developing a library, we will implement it in a simple TLS-terminating web proxy, and time permitting, as a module for nginx. Cryptographic functions are currently provided by FFI bindings to libsodium.

#### Building

You will need to have both ```libclang``` and ```libsodium``` installed on your system. On Debian flavoured machines, you can install libclang from the clang package (```sudo apt-get install clang```). You can download the latest version of libsodium from source and manually make/make install it.

```
Download the latest tarball from: https://download.libsodium.org/libsodium/releases/
Navigate into the directory
./configure
make
sudo make install
sudo ldconfig
```

Afterwards, ```cargo``` should work for building this project.

#### Related Projects

The main related project is [rustls](https://github.com/ctz/rustls), which is a Rust implementation of TLS. It implements TLS using the [ring](https://github.com/briansmith/ring) crypto library, which builds on BoringSSL. It aims to be a fully featured implementation of TLS in a more complex API.

#### Resources

- [Amazon s2n](https://github.com/awslabs/s2n): a security-focused implementation of TLS/SSL from Amazon Security.
- [TLS 1.3 spec](https://tlswg.github.io/tls13-spec): This spec describes the minimum required features to be compliant
