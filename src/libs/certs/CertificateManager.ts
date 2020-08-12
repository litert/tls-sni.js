/**
 * Copyright 2020 Angus.Fenying <fenying@litert.org>
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

import * as C from './Common';
import * as E from '../Errors';
import * as X509 from '../x509';
import * as TLS from 'tls';
import * as RSA from '../rsa';

interface ICertificateInfo {

    rawCert: Buffer | string;

    privateKey: Buffer | string;

    cert: X509.ICertificate;

    context: TLS.SecureContext;
}

class CertificateManager implements C.ICertificateManager {

    private _certs: Record<string, ICertificateInfo>;

    private _x509: X509.IDecoder;

    private _rsaPriv: RSA.IPrivateDecoder;

    private _cache!: Record<
        'simple' | 'wildcard',
        Record<string, string>
    >;

    private _sniCallback: C.TSNICallback;

    public constructor() {

        this._cache = {
            simple: {},
            wildcard: {}
        };

        this._x509 = X509.createDecoder();

        this._rsaPriv = RSA.createPrivateKeyDecoder();

        this._certs = {};

        this._sniCallback = (new Function(
            'cc', 'cs', 'E', `return function(subject, cb) {

                subject = subject.toLowerCase();

                if (cc.simple[subject] !== undefined) {

                    return cb(null, cs[cc.simple[subject]].context);
                }

                const wsEntry = subject.substr(subject.indexOf(".") + 1);

                if (cc.wildcard[wsEntry] !== undefined) {

                    return cb(null, cs[cc.wildcard[wsEntry]].context);
                }

                return cb(new E({ metadata: { subject } }));
            };`
        ))(this._cache, this._certs, E.E_UNKNOWN_SERVER_NAME);
    }

    public use(
        name: string,
        certificate: Buffer | string,
        privateKey: Buffer | string,
        extOptions: TLS.SecureContextOptions = {}
    ): this {

        this._certs[name] = {
            'rawCert': certificate,
            'privateKey': privateKey,
            'cert': this._x509.decode(certificate),
            'context': TLS.createSecureContext({
                ...extOptions,
                key: privateKey,
                cert: certificate
            })
        };

        this._buildCache();

        return this;
    }

    public clear(): void {

        for (const name in this._certs) {

            delete this._certs[name];
        }

        this._buildCache();
    }

    public findExpiringCertificates(
        t: number = Date.now() + 7 * 86400000
    ): string[] {

        const ret: string[] = [];

        for (const key in this._certs) {

            if (this._certs[key].cert.details.validity.notAfter.getTime() <= t) {

                ret.push(key);
            }
        }

        return ret;
    }

    public validate(
        cert: Buffer | string,
        privKey: Buffer | string
    ): boolean {

        let c = this._x509.decode(cert);

        if (!c.details.publicKey.algorithm.name.includes('RSA')) {

            return false;
        }

        try {

            let p = this._rsaPriv.decode(privKey);

            return !(c.details.publicKey.value as any).modulus.compare(
                p.modulus
            );
        }
        catch {

            return false;
        }
    }

    public remove(name: string): boolean {

        if (!this._certs[name]) {

            return false;
        }

        delete this._certs[name];

        this._buildCache();

        return true;
    }

    public test(subject: string): string | null {

        subject = subject.toLowerCase();

        if (this._cache.simple[subject] !== undefined) {

            return this._cache.simple[subject];
        }

        /**
         * Extract the part after the first DOT symbol as the entry of a
         * wildcard subject.
         *
         * If not DOT exists in the subject, it will be the whole subject.
         * (-1 plus 1 makes 0)
         */
        const wsEntry = subject.substr(subject.indexOf('.') + 1);

        if (this._cache.wildcard[wsEntry] !== undefined) {

            return this._cache.wildcard[wsEntry];
        }

        return null;
    }

    public getCertificate(name: string): X509.ICertificate {

        if (!this._certs[name]) {

            throw new E.E_NO_CERT({ metadata: { name } });
        }

        return this._certs[name].cert;
    }

    public getContext(name: string): TLS.SecureContext {

        if (!this._certs[name]) {

            throw new E.E_NO_CERT({ metadata: { name } });
        }

        return this._certs[name].context;
    }

    private _buildCache(): void {

        this._cache.simple = {};
        this._cache.wildcard = {};

        const E_CN = 'Common Name';
        const E_SAN = 'Subject Alternative Name';

        for (let name in this._certs) {

            const info = this._certs[name];

            const details = info.cert.details;

            this._addCache(details.subject[E_CN], name);

            if (details.extensions?.[E_SAN]) {

                for (const cn of details.extensions[E_SAN].value) {

                    this._addCache(cn, name);
                }
            }
        }
    }

    private _addCache(subject: string, certName: string): void {

        subject = subject.toLowerCase();

        /**
         * A wildcard subject must start with an asterisk and a dot.
         */
        if (subject.startsWith('*.')) {

            /**
             * Use the part after the first DOT symbol as the entry of the
             * subject.
             */
            subject = subject.slice(2);

            /**
             * Only one asterisk is allowed in a subject.
             */
            if (subject.includes('*')) {

                throw new E.E_INVALID_WILDCARD({ metadata: { subject } });
            }

            this._cache.wildcard[subject] = certName;
        }
        else {

            /**
             * A wildcard subject must start with an asterisk and a dot.
             */
            if (subject.includes('*')) {

                throw new E.E_INVALID_WILDCARD({ metadata: { subject } });
            }

            this._cache.simple[subject] = certName;
        }
    }

    public getSNICallback(): C.TSNICallback {

        return this._sniCallback;
    }
}

export function createManager(): C.ICertificateManager {

    return new CertificateManager();
}
