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
import * as E from "../Errors";
import * as A from "../Abstracts";

const PRIV_START = "-----BEGIN RSA PRIVATE KEY-----";
const PRIV_ENDING = "-----END RSA PRIVATE KEY-----";

class RSAPrivateKeyDecoder
extends A.AbstractPEMDecoder
implements C.IPrivateDecoder {

    private _der = DER.createDecoder();

    public constructor() {

        super(
            PRIV_START,
            PRIV_ENDING,
            E.E_INVALID_RSA_KEY
        );
    }

    public decode(cert: Buffer | string): C.IPrivateKey {

        if (typeof cert === "string" || this.isPEM(cert)) {

            cert = this.pem2DER(cert);
        }
        else if (!this.isDER(cert)) {

            throw new E.E_INVALID_RSA_KEY();
        }

        const derStruct: C.TPrivateKeySkeleton = this._der.decode(cert) as any;

        return {
            version: derStruct.data[0].data === 0 ? "prime" : "multi",
            modulus: derStruct.data[1].data as Buffer,
            publicExponent: derStruct.data[2].data,
            privateExponent: derStruct.data[3].data as Buffer,
            prime1: derStruct.data[4].data as Buffer,
            prime2: derStruct.data[5].data as Buffer,
            exponent1: derStruct.data[6].data as Buffer,
            exponent2: derStruct.data[7].data as Buffer,
            coefficient: derStruct.data[8].data as Buffer,
        };
    }
}

export function createPrivateKeyDecoder(): C.IPrivateDecoder {

    return new RSAPrivateKeyDecoder();
}
