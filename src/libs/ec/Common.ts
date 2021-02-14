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

import {

    TSequence,
    TInteger,
    IElement,
    ETClass,
    ETKind,
    TBitString,
    TChoice,
    TOID

} from '../der/Common';

export type TPrivateKeySkeleton = TSequence<[
    TInteger,
    TInteger,
    TChoice<TOID>,
    IElement<ETClass.CONTEXT, 1, TBitString>
]>;

export type TPublicKeySkeleton = TSequence<[
    TSequence<[
        TOID,
        TOID
    ]>,
    TBitString
]>;

export interface IPrivateKey {

    /**
     * Type of key.
     */
    'version': number;

    /**
     * The private key.
     */
    'privateKey': Buffer;

    /**
     * The OID of named curve.
     */
    'namedCurve'?: string;

    /**
     * The EC public key bundled in the private key.
     */
    'publicKey'?: Buffer;
}

export interface IPublicKey {

    /**
     * The OID of named curve.
     */
    'namedCurve': string;

    /**
     * The EC public key.
     */
    'publicKey': Buffer;
}

export interface IPrivateDecoder {

    decode(key: Buffer | string): IPrivateKey;
}

export interface IPublicDecoder {

    decode(key: Buffer | string): IPublicKey;

    decodeFromDER(der: any): IPublicKey;
}

export type TECPubKey = IElement<ETClass.UNIVERSAL, ETKind.OCTET_STRING, Buffer>;
