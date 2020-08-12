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

import {

    TSequence,
    TInteger,
    IElement,
    ETClass,
    ETKind,
    TBitString

} from '../der/Common';

export type TPrivateKeySkeleton = TSequence<[
    TInteger,
    TInteger,
    TInteger,
    TInteger,
    TInteger,
    TInteger,
    TInteger,
    TInteger,
    TInteger
]>;

export type TPublicKeySkeleton = TSequence<[
    TSequence<[
        IElement<ETClass.UNIVERSAL, ETKind.OID>,
        IElement<ETClass.UNIVERSAL, any>
    ]>,
    TBitString
]>;

export interface IPrivateKey {

    /**
     * Type of key.
     */
    'version': 'prime' | 'multi';

    /**
     * Public moduls n
     */
    'modulus': Buffer;

    /**
     * Public exponent e
     */
    'publicExponent': number | Buffer;

    /**
     * Private exponent d
     */
    'privateExponent': Buffer;

    /**
     * Secret prime p
     */
    'prime1': Buffer;

    /**
     * Secret prime q
     */
    'prime2': Buffer;

    /**
     * dp = d mod (p - 1)
     */
    'exponent1': Buffer;

    /**
     * dq = d mode (q - 1)
     */
    'exponent2': Buffer;

    'coefficient': Buffer;
}

export interface IPublicKey {

    /**
     * Public moduls n
     */
    'modulus': Buffer;

    /**
     * Public exponent e
     */
    'publicExponent': number | Buffer;
}

export interface IPrivateDecoder {

    decode(key: Buffer | string): IPrivateKey;
}

export interface IPublicDecoder {

    decode(key: Buffer | string): IPublicKey;
}

export type TRSAPubKey = TSequence<[
    TInteger,
    TInteger
]>;
