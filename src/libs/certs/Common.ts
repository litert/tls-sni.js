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

    /**
     * Remove a existed certificate by its name.
     *
     * @param name The name of certificate to be removed.
     */
    remove(name: string): boolean;

    /**
     * Setup a certificate. If the name of certificate already exists, the
     * current certificate will be overwritten.
     *
     * @param name          The name of new certificate.
     * @param cert          The content of new certificate.
     * @param privateKey    The content of private key against the new certificate.
     * @param extOptions    (Optional) Extra options for the TLS secure context.
     */
    use(
        name: string,
        cert: Buffer | string,
        privateKey: Buffer | string,
        extOptions?: TLS.SecureContextOptions
    ): this;

    /**
     * Check and find the name of certificate that the specific hostname will
     * use.
     *
     * If no matched certificate, null will be returned.
     *
     * @param hostname  The hostname to be tested.
     */
    test(hostname: string): string | null;

    /**
     * Get the decoded information of specific certificate.
     *
     * @param name The name of certificate.
     */
    getCertificate(name: string): X509.ICertificate;

    /**
     * Get the TLS secure context of specific certificate.
     *
     * @param name The name of certificate.
     */
    getContext(name: string): TLS.SecureContext;

    /**
     * Get the callback of SNI.
     */
    getSNICallback(): TSNICallback;
}