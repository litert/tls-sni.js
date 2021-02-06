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
import * as DER from '../der';
import * as O from '../oid';
import * as E from '../Errors';
import * as A from '../Abstracts';

const PUB_START = '-----BEGIN PUBLIC KEY-----';
const PUB_ENDING = '-----END PUBLIC KEY-----';

class RSAPublicKeyDecoder
    extends A.AbstractPEMDecoder
    implements C.IPublicDecoder {

    private _der = DER.createDecoder();

    public constructor() {

        super(
            PUB_START,
            PUB_ENDING,
            E.E_INVALID_RSA_KEY
        );
    }

    public decode(cert: Buffer | string): C.IPublicKey {

        if (typeof cert === 'string' || this.isPEM(cert)) {

            cert = this.pem2DER(cert);
        }
        else if (!this.isDER(cert)) {

            throw new E.E_INVALID_RSA_KEY();
        }

        return this.decodeFromDER(this._der.decode(cert) as any);
    }

    public decodeFromDER(derStruct: C.TPublicKeySkeleton): C.IPublicKey {

        const algo = O.oid2Name(derStruct.data[0].data[0].data);

        if (!algo.includes('RSA')) {

            throw new E.E_INVALID_RSA_KEY();
        }

        const pubKey = this._der.decode(derStruct.data[1].data.value) as C.TRSAPubKey;

        return {
            'modulus': pubKey.data[0].data as Buffer,
            'publicExponent': pubKey.data[1].data
        };
    }
}

export function createPublicKeyDecoder(): C.IPublicDecoder {

    return new RSAPublicKeyDecoder();
}
