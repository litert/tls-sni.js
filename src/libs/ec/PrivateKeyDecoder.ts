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

import * as C from './Common';
import * as DER from '../der';
import * as E from '../Errors';
import * as A from '../Abstracts';

const PRIV_START = '-----BEGIN EC PRIVATE KEY-----';
const PRIV_ENDING = '-----END EC PRIVATE KEY-----';

class ECPrivateKeyDecoder extends A.AbstractPEMDecoder implements C.IPrivateDecoder {

    private _der = DER.createDecoder();

    public constructor() {

        super(
            PRIV_START,
            PRIV_ENDING,
            E.E_INVALID_EC_KEY
        );
    }

    public decode(cert: Buffer | string): C.IPrivateKey {

        if (typeof cert === 'string' || this.isPEM(cert)) {

            cert = this.pem2DER(cert);
        }
        else if (!this.isDER(cert)) {

            throw new E.E_INVALID_EC_KEY();
        }

        const derStruct: C.TPrivateKeySkeleton = this._der.decode(cert) as any;

        return {
            'version': derStruct.data[0].data as number,
            'privateKey': derStruct.data[1].data as Buffer,
            'namedCurve': derStruct.data[2]?.data?.data,
            'publicKey': derStruct.data[3]?.data.data.value
        };
    }
}

export function createPrivateKeyDecoder(): C.IPrivateDecoder {

    return new ECPrivateKeyDecoder();
}
