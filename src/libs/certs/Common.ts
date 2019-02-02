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

import * as TLS from "tls";
import * as X509 from "../x509";

export type TSNICallback = TLS.TlsOptions["SNICallback"];

export interface ICertificateManager {

    remove(name: string): boolean;

    set(
        name: string,
        cert: Buffer | string,
        privateKey: Buffer | string,
        extOptions?: TLS.SecureContextOptions
    ): this;

    test(hostname: string): string | null;

    getCertificate(name: string): X509.ICertificate;

    getSNICallback(): TSNICallback;
}
