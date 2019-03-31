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

import * as L from "@litert/core";

export class AbstractPEMDecoder {

    public constructor(
        private _PEM_START: string,
        private _PEM_ENDING: string,
        private _ERROR: L.IErrorConstructor<any>
    ) {}

    public isPEM(cert: Buffer | string): boolean {

        return cert.indexOf(this._PEM_START) === 0 &&
                cert.indexOf(this._PEM_ENDING) > this._PEM_START.length;
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

        const ep = cert.indexOf(this._PEM_ENDING);

        if (!cert.startsWith(this._PEM_START) || ep === -1) {

            throw new this._ERROR();
        }

        return Buffer.from(
            cert.substr(
                this._PEM_START.length,
                ep - this._PEM_START.length
            ).replace(/\n/g, ""),
            "base64"
        );
    }

    public der2PEM(cert: Buffer): string {

        return `${
            this._PEM_START
        }\n${
            cert.toString("base64").replace(/(.{1, 64})/g, "$1\n")
        }\n${
            this._PEM_ENDING
        }`;
    }
}
