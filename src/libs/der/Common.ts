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

export enum ETKind {

    RESERVED_0,
    BOOLEAN,
    INTEGER,
    BIT_STRING,
    OCTET_STRING,
    NULL,
    OID,
    OBJECT_DESCRIPTION,
    INSTANCE_OF,
    REAL,
    ENUMERATED,
    EMBEDDED_PDV,
    UTF8_STRING,
    RELATIVE_OID,
    RESERVED_1,
    RESERVED_2,
    SEQUENCE,
    SET,
    NUMERIC_STRING,
    PRINTABLE_STRING,
    T61_STRING,
    VIDEOTEX_STRING,
    IA5_STRING,
    UTC_TIME,
    GENERALIZED_TIME,
    GRAPHIC_STRING,
    VISIBLE_STRING,
    GENERAL_STRING,
    UNIVERSAL_STRING,
    CHARACTER_STRING,
    BMP_STRING,
    RESERVED_3

}

export enum ETClass {

    UNIVERSAL,
    APPLICATION,
    CONTEXT,
    PRIVATE
}

export interface ITag<
    TC extends ETClass = ETClass,
    TE extends ETKind = ETKind
> {

    class: TC;

    constructed: boolean;

    type: TE;
}

export interface IElement<
    TC extends ETClass = ETClass,
    TE extends ETKind = ETKind,
    TD = any
> {

    tag: ITag<TC, TE>;

    data: TD;
}

export interface IDecoder {

    decode(data: Buffer): IElement;
}

export interface IBitStringContent {
    appended: number;
    value: Buffer;
}

export type TBitString = IElement<ETClass.UNIVERSAL, ETKind.BIT_STRING, IBitStringContent>;

export type TInteger = IElement<ETClass.UNIVERSAL, ETKind.INTEGER, number | Buffer>;

export type TLongInteger = IElement<ETClass.UNIVERSAL, ETKind.INTEGER, Buffer>;

export type TShortInteger = IElement<ETClass.UNIVERSAL, ETKind.INTEGER, number>;

export type TSequence<T extends Array<IElement | undefined>> = IElement<
    ETClass.UNIVERSAL,
    ETKind.SEQUENCE,
    T
>;

export type TSet<T extends IElement> = IElement<
    ETClass.UNIVERSAL,
    ETKind.SET,
    T[]
>;

export type TOID = IElement<ETClass.UNIVERSAL, ETKind.OID, string>;

export type TUTCTime = IElement<ETClass.UNIVERSAL, ETKind.UTC_TIME, Date>;

export type TGeneralizedTime = IElement<
    ETClass.UNIVERSAL,
    ETKind.GENERALIZED_TIME,
    Date
>;
