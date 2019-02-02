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
import * as E from "../Errors";
import * as X509 from "../x509";
import * as TLS from "tls";

interface ICertificateInfo {

    rawCert: Buffer | string;

    privateKey: Buffer | string;

    cert: X509.ICertificate;

    context: TLS.SecureContext;
}

class CertificateManager implements C.ICertificateManager {

    private _certs: Record<string, ICertificateInfo>;

    private _x509: X509.IDecoder;

    private _cache!: Record<
        "simple" | "wildcard",
        Record<string, string>
    >;

    private _sniCallback: C.TSNICallback;

    public constructor() {

        this._cache = {
            simple: {},
            wildcard: {}
        };

        this._x509 = X509.createDecoder();

        this._certs = {};

        this._sniCallback = (new Function(
            `cc`, `cs`, `E`, `return function(hostname, cb) {

                hostname = hostname.toLowerCase();

                if (cc.simple[hostname] !== undefined) {

                    return cb(null, cs[cc.simple[hostname]].context);
                }

                for (const cna in cc.wildcard) {

                    if (hostname.endsWith(cna)) {

                        cc.simple[hostname] = cc.wildcard[cna];
                        return cb(null, cs[cc.wildcard[cna]].context);
                    }
                }

                return cb(new E({ metadata: { hostname } }));
            };`
        ))(this._cache, this._certs, E.E_UNKNOWN_SERVER_NAME) as any;
    }

    public set(
        name: string,
        certificate: Buffer | string,
        privateKey: Buffer | string,
        extOptions: TLS.SecureContextOptions = {}
    ): this {

        if (this._certs[name]) {

            throw new E.E_DUP_CERT({
                metadata: { name, certificate, privateKey }
            });
        }

        this._certs[name] = {
            rawCert: certificate,
            privateKey,
            cert: this._x509.decode(certificate),
            context: TLS.createSecureContext({
                ...extOptions,
                key: privateKey,
                cert: certificate
            })
        };

        this._buildCache();

        return this;
    }

    public remove(name: string): boolean {

        if (!this._certs[name]) {

            return false;
        }

        delete this._certs[name];

        this._buildCache();

        return true;
    }

    public test(hostname: string): string | null {

        hostname = hostname.toLowerCase();

        if (this._cache.simple[hostname] !== undefined) {

            return this._cache.simple[hostname];
        }

        for (const cna in this._cache.wildcard) {

            if (hostname.endsWith(cna)) {

                return this._cache.wildcard[cna];
            }
        }

        return null;
    }

    public getCertificate(name: string): X509.ICertificate {

        if (!this._certs[name]) {

            throw new E.E_NO_CERT({ metadata: { name } });
        }

        return this._certs[name].cert;
    }

    private _buildCache(): void {

        this._cache.simple = {};
        this._cache.wildcard = {};

        const E_CN = "Common Name";
        const E_SAN = "Subject Alternative Name";

        for (let name in this._certs) {

            const info = this._certs[name];

            const details = info.cert.details;

            this._addCache(details.subject[E_CN], name);

            if (details.extensions && details.extensions[E_SAN]) {

                for (const cn of details.extensions[E_SAN].value) {

                    this._addCache(cn, name);
                }
            }
        }
    }

    private _addCache(cn: string, certName: string): void {

        if (cn.startsWith("*")) {

            this._cache.wildcard[cn.slice(1)] = certName;
        }
        else {

            this._cache.simple[cn] = certName;
        }
    }

    public getSNICallback(): C.TSNICallback {

        return this._sniCallback;
    }
}

export function createManager(): C.ICertificateManager {

    return new CertificateManager();
}
