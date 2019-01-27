/**
 * Copyright 2019 Angus.Fenying <fenying@litert.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as C from "./Common";
import * as DER from "../der";

const X509_START = "-----BEGIN CERTIFICATE-----";
const X509_ENDING = "-----END CERTIFICATE-----";

class X509Decoder implements C.IDecoder {

    private _der = DER.createDecoder();

    public decode(cert: Buffer | string): C.ICertificate {

        const ret: C.ICertificate = {
            details: {
                version: 1,
                serial: null as any,
                algorithm: {
                    name: "",
                    args: null
                },
                issuer: {},
                subject: {},
                validity: {
                    notAfter: null as any,
                    notBefore: null as any
                },
                publicKey: {
                    algorithm: {
                        name: "",
                        args: null
                    },
                    value: null as any
                },
                extensions: {}
            },
            signature: {
                algorithm: {
                    name: "",
                    args: null
                },
                value: null as any
            }
        };

        if (typeof cert === "string" || this.isPEM(cert)) {

            cert = this.pem2DER(cert);
        }
        else if (!this.isDER(cert)) {

            throw new Error("Not a valid X.509 certificate.");
        }

        const data: C.TSkeleton = this._der.decode(cert) as any;

        this._parseSignature(data, ret);

        return ret;
    }

    private _parseSignature(dc: C.TSkeleton, output: C.ICertificate): void {

        const signAlgo = dc.data[1];

        output.signature.algorithm.name = C.OID_NAMES[signAlgo.data[0].data];
        output.signature.algorithm.args = signAlgo.data[1].data;
        output.signature.value = dc.data[2].data;
    }

    public isPEM(cert: Buffer | string): boolean {

        return cert.indexOf(X509_START) === 0 &&
                cert.indexOf(X509_ENDING) > X509_START.length;
    }

    public isDER(cert: Buffer): boolean {

        return cert[0] === 0x30;
    }

    public pem2DER(cert: Buffer | string): Buffer {

        if (cert instanceof Buffer) {

            cert = cert.toString();
        }

        cert = cert
        .replace(/\r\n/, "\n")
        .replace(/\r/, "\n")
        .replace(/^\n|\n$/, "")
        .replace(/\n+/, "\n");

        const ep = cert.indexOf(X509_ENDING);

        if (!cert.startsWith(X509_START) || ep === -1) {

            throw new Error("Not a X.509 certificate in PEM format.");
        }

        return Buffer.from(
            cert.substr(
                X509_START.length,
                ep - X509_START.length
            ).replace(/\n/g, ""),
            "base64"
        );
    }

    public der2PEM(cert: Buffer): string {

        return `${
            X509_START
        }\n${
            cert.toString("base64").replace(/(.{1, 64})/g, "$1\n")
        }\n${
            X509_ENDING
        }`;
    }
}

export function createDecoder(): C.IDecoder {

    return new X509Decoder();
}
