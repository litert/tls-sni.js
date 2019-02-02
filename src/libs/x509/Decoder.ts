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
import * as U from "./Utility";
import * as O from "./OID";
import * as E from "../Errors";

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

            throw new E.E_INVALID_X509();
        }

        const derStruct: C.TSkeleton = this._der.decode(cert) as any;

        this._readAlgorithm(
            derStruct.data[1],
            ret.signature.algorithm
        );

        ret.signature.value = derStruct.data[2].data;

        const tbsc = derStruct.data[0].data;
        ret.details.version = tbsc[0].data.data + 1;

        ret.details.serial = tbsc[1].data as Buffer;

        this._readAlgorithm(tbsc[2], ret.details.algorithm);

        this._readIssuerInfo(tbsc[3], ret.details.issuer);

        ret.details.validity.notBefore = tbsc[4].data[0].data;

        ret.details.validity.notAfter = tbsc[4].data[1].data;

        this._readIssuerInfo(tbsc[5], ret.details.subject);

        ret.details.validity.notBefore = tbsc[4].data[0].data;

        ret.details.validity.notAfter = tbsc[4].data[1].data;

        this._readAlgorithm(
            tbsc[6].data[0],
            ret.details.publicKey.algorithm
        );

        for (let i = 7; i < tbsc.length; i++) {

            const prop = tbsc[i];

            if (!prop || prop.tag.class !== DER.ETClass.CONTEXT) {

                continue;
            }

            switch (prop.tag.type) {
            case 1:
                ret.details.issuerUniqueID = prop.data.data;
                break;
            case 2:
                ret.details.subjectUniqueID = prop.data.data;
                break;
            case 3:

                for (let x of prop.data.data) {

                    const extInfo: C.IExtensionItem = {
                        value: null,
                        critical: x.data.length === 3
                    };

                    let extData: DER.IElement;

                    switch (x.data[0].data) {
                    case O.X509_EXT_KEY_USAGE:

                        extData = this._der.decode(x.data[2].data);

                        // tslint:disable-next-line:no-bitwise
                        extInfo.value = extData.data.value[0] >> extData.data.appended;

                        break;

                    case O.X509_EXT_SUBJ_ALTER_NAMES:

                        extData = this._der.decode(x.data[1].data);
                        extInfo.value = extData.data.map(
                            (d: DER.IElement) => d.data.toString()
                        );

                        break;

                    case O.X509_EXT_EX_KEY_USAGE:

                        extInfo.value = this._der.decode(x.data[1].data).data.map(
                            (v: any) => v.data
                        );

                        break;

                    case O.X509_EXT_EX_KEY_USAGE:

                        extInfo.value = this._der.decode(x.data[1].data).data.map(
                            (v: any) => v.data
                        );

                        break;

                    case O.X509_EXT_BASIC_CONSTRAINTS:

                        extInfo.value = x.data[1].data;

                        break;

                    case O.X509_EXT_SUBJ_IDENTIFIER:

                        extInfo.value = this._der.decode(x.data[1].data).data;

                        break;

                    default:

                        extInfo.value = x.data[extInfo.critical ? 2 : 1].data;
                    }

                    ret.details.extensions[U.oid2Name(x.data[0].data)] = extInfo;
                }
                break;
            }
        }

        ret.details.publicKey.value = tbsc[6].data[1].data;

        return ret;
    }

    private _readIssuerInfo(
        data: DER.TSequence<Array<DER.TSet<DER.TSequence<[DER.TOID, DER.IElement]>>>>,
        output: Record<string, any>
    ): void {

        for (let x of data.data) {

            output[U.oid2Name(x.data[0].data[0].data)] = x.data[0].data[1].data;
        }
    }

    private _readAlgorithm(dc: DER.IElement, output: C.IAlgorithm): void {

        output.name = U.oid2Name(dc.data[0].data);
        output.args = dc.data[1].data;
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

            throw new E.E_INVALID_X509();
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
