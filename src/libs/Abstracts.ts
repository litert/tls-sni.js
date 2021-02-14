/**
 * Copyright 2021 Angus.Fenying <fenying@litert.org>
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

import * as $Exceptions from '@litert/exception';

export class AbstractPEMDecoder {

    public constructor(
        private _pemStarting: string,
        private _pemEnding: string,
        private _error: $Exceptions.IExceptionConstructor
    ) {}

    public isPEM(cert: Buffer | string): boolean {

        return cert.indexOf(this._pemStarting) === 0 &&
                cert.indexOf(this._pemEnding) > this._pemStarting.length;
    }

    public isDER(cert: Buffer): boolean {

        return cert[0] === 0x30;
    }

    public pem2DER(cert: Buffer | string): Buffer {

        if (cert instanceof Buffer) {

            cert = cert.toString();
        }

        cert = cert
            .replace(/\r\n/, '\n')
            .replace(/\r/, '\n')
            .replace(/^\n|\n$/, '')
            .replace(/\n+/, '\n');

        const ep = cert.indexOf(this._pemEnding);

        if (!cert.startsWith(this._pemStarting) || ep === -1) {

            throw new this._error();
        }

        return Buffer.from(
            cert.substr(
                this._pemStarting.length,
                ep - this._pemStarting.length
            ).replace(/\r|\n/g, ''),
            'base64'
        );
    }

    public der2PEM(cert: Buffer): string {

        return `${
            this._pemStarting
        }\n${
            cert.toString('base64').replace(/(.{1, 64})/g, '$1\n')
        }\n${
            this._pemEnding
        }`;
    }
}
