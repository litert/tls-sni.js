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

import {

    IElement,
    ETClass,
    ETKind,
    TSequence,
    TBitString,
    TInteger,
    TShortInteger,
    TSet,
    TOID,
    TUTCTime,
    TGeneralizedTime,
    IBitStringContent

} from "../der/Common";

export interface IDecoder {

    decode(cert: Buffer | string): ICertificate;
}

export interface IExtensionItem<T = any> {

    critical: boolean;

    value: T;
}

export interface IAlgorithm {

    name: string;

    args: any;
}

export interface ICertificate {

    details: {

        version: number;

        serial: Buffer;

        algorithm: IAlgorithm;

        issuer: Record<string, any>;

        subject: Record<string, any>;

        validity: {

            notBefore: Date;

            notAfter: Date;
        };

        publicKey: {

            algorithm: IAlgorithm;

            value: IBitStringContent | {

                modulus: Buffer;

                publicExponent: number | Buffer;
            };
        };

        issuerUniqueID?: IBitStringContent;

        subjectUniqueID?: IBitStringContent;

        extensions: Record<string, IExtensionItem>;
    };

    signature: {

        algorithm: IAlgorithm;

        value: IBitStringContent;
    };
}

export type TAlgorithmIdentifier = TSequence<[
    IElement<ETClass.UNIVERSAL, ETKind.OID>,
    IElement<ETClass.UNIVERSAL, any>
]>;

export type TTime = TUTCTime | TGeneralizedTime;

export type TExtensions = IElement<ETClass.CONTEXT, 3, TSequence<
    Array<TSequence<[TOID, ...IElement[]]>>
>>;

export type TSkeleton = TSequence<[
    TSequence<[
        IElement<ETClass.CONTEXT, 0, TShortInteger>,
        TInteger,
        TAlgorithmIdentifier,
        TSequence<Array<TSet<TSequence<[TOID, IElement]>>>>,
        TSequence<[TTime, TTime]>,
        TSequence<Array<TSet<TSequence<[TOID, IElement]>>>>,
        TSequence<[TAlgorithmIdentifier, TBitString]>,
        IElement?,
        IElement?,
        IElement?
    ]>,
    TAlgorithmIdentifier,
    TBitString
]>;

export interface IDecoder {

    /**
     * Decode the certificate into readable structure..
     *
     * @param cert The content of certificate to be decoded.
     */
    decode(cert: Buffer | string): ICertificate;

    /**
     * Check if a certificate is in PEM encoding.
     *
     * @param cert The content of certificate to be checked.
     */
    isPEM(cert: Buffer | string): boolean;

    /**
     * Check if a certificate is in DER encoding.
     *
     * @param cert The content of certificate to be checked.
     */
    isDER(cert: Buffer): boolean;

    /**
     * Convert a certificate from DER-PEM encoding to DER encoding.
     *
     * @param cert The certificate in PEM encoding.
     */
    pem2DER(cert: Buffer | string): Buffer;

    /**
     * Convert a certificate from DER encoding to PEM-DER encoding.
     *
     * @param cert The certificate in DER encoding.
     */
    der2PEM(cert: Buffer): string;
}
