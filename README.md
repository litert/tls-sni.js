# LiteRT/TLS-SNI

[![npm version](https://img.shields.io/npm/v/@litert/tls-sni.svg?colorB=brightgreen)](https://www.npmjs.com/package/@litert/tls-sni "Stable Version")
[![License](https://img.shields.io/npm/l/@litert/tls-sni.svg?maxAge=2592000?style=plastic)](https://github.com/litert/tls-sni/blob/master/LICENSE)
[![node](https://img.shields.io/node/v/@litert/tls-sni.svg?colorB=brightgreen)](https://nodejs.org/dist/latest-v8.x/)
[![GitHub issues](https://img.shields.io/github/issues/litert/tls-sni.js.svg)](https://github.com/litert/tls-sni.js/issues)
[![GitHub Releases](https://img.shields.io/github/release/litert/tls-sni.js.svg)](https://github.com/litert/tls-sni.js/releases "Stable Release")

A TLS SNI(Server Name Indication) library for Node.js.

## Features

- [x] TypeScript Supports.
- [x] X.509 Certificate Decoder
- [x] Partial DER Decoder
- [x] Certificate Manager
- [x] Graceful Update Certificate.
- [ ] ECC Certificate Supports.

## Requirement

- TypeScript v3.2.x (or newer)
- Node.js v10.0.0 (or newer)

## Installation

```sh
npm i @litert/tls-sni --save
```

## Usage

```ts
import * as libsni from "@litert/tls-sni";
import * as TLS from "tls";
import * as FS from "fs";

// 1. Create a certificate mananger object.
const cm = libsni.certs.createManager();

// 2. Load a certificate into certificate mananger
cm.use(
    "default",
    FS.readFileSync(`./certs/default/cert-20190801.pem`),
    FS.readFileSync(`./certs/default/key-20190801.pem`)
);

// 3. Create a TLS server with the SNI callback provided by ceritificate manager.
const server = TLS.createServer({
    SNICallback: cm.getSNICallback(),
    ...otherOptions
});

// ...

// 4. Check if there are some certificates outdating.

const outdatingCerts = cm.findExpiringCertificates(
    Date.now() + 28 * 86400000 // Optional, 7 days by default
); // Get the list of certificate names, which are outdating in 28 days.

// ...

// 5. When a cert is being outdated, replace it with a new one.
cm.use(
    "default",
    FS.readFileSync(`./certs/default/cert-20190901.pem`),
    FS.readFileSync(`./certs/default/key-20190901.pem`)
);
```

## Document

Preparing yet.

## License

This library is published under [Apache-2.0](./LICENSE) license.
