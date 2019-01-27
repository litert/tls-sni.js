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

// tslint:disable:no-bitwise
import * as C from "./Common";

class Decoder implements C.IDecoder {

    public decode(data: Buffer): C.IElement {

        return this._decode(data, 0)[1];
    }

    private _decode(data: Buffer, offset: number): [number, C.IElement] {

        let tag: C.ITag;

        [offset, tag] = this._readTag(data, offset);

        switch (tag.class) {

        case C.ETClass.UNIVERSAL:

            switch (tag.type) {
            case C.ETKind.NULL:
                return this._decodeNull(tag, data, offset);
            case C.ETKind.BOOLEAN:
                return this._decodeBoolean(tag, data, offset);
            case C.ETKind.BIT_STRING:
                return this._decodeBitString(tag, data, offset);
            case C.ETKind.OCTET_STRING:
                return this._decodeRawData(tag, data, offset);
            case C.ETKind.PRINTABLE_STRING:
                return this._decodePrintableString(tag, data, offset);
            case C.ETKind.UTF8_STRING:
                return this._decodePrintableString(tag, data, offset);
            case C.ETKind.INTEGER:
                return this._decodeInteger(tag, data, offset);
            case C.ETKind.SET:
            case C.ETKind.SEQUENCE:
                return this._decodeSequence(tag, data, offset);
            case C.ETKind.OID:
                return this._decodeOID(tag, data, offset);
            case C.ETKind.UTC_TIME:
                return this._decodeUTCTime(tag, data, offset);
            default:
                return this._decodeRawData(tag, data, offset);
            }

        default:

            if (tag.constructed) {

                return this._decodeNest(tag, data, offset);
            }
            return this._decodeRawData(tag, data, offset);
            // throw new Error(`${ETagClass[tag.class]} type of tag is not supported yet.`);
        }
    }

    private _decodeSequence(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        let sequences: C.IElement[] = [];

        for (const ENDING = offset + length; offset < ENDING; ) {

            let item: C.IElement;

            [offset, item] = this._decode(data, offset);

            sequences.push(item);
        }

        return [offset, {
            tag,
            data: sequences
        }];
    }

    private _decodeNest(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        return [offset + length, {
            tag,
            data: this._decode(data, offset)[1]
        }];
    }

    private _decodeNull(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        [offset] = this._readLength(data, offset);

        return [offset, {
            tag,
            data: null
        }];
    }

    private _decodeInteger(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        let x = data[offset] ? 0 : 1;

        if (length - x > 6) {

            return [offset + length, {
                tag,
                data: data.slice(offset, offset + length)
            }];
        }

        let tmp = Buffer.alloc(6);

        data.copy(tmp, 6 - (length - x), offset, offset + length - x);

        if (x) {

            if (length - x < 6) {

                tmp.fill(0xFF, 6 - length + x, 6);
            }
        }

        return [offset + length, {
            tag,
            data: tmp.readUInt32BE(0) * 0x10000 + tmp.readUInt16BE(4)
        }];
    }

    /**
     * YYMMDDhhmmZ
     * YYMMDDhhmm+HHMm
     * YYMMDDhhmm-HHMm
     * YYMMDDhhmmssZ
     * YYMMDDhhmmss+HHMm
     * YYMMDDhhmmss-HHMm
     */
    private _decodeUTCTime(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        const yy = parseInt(data.toString("utf8", offset, offset + 2));
        const y = yy >= 40 ? (1900 + yy) : (2000 + yy);
        const m = data.toString("utf8", offset + 2, offset + 4);
        const d = data.toString("utf8", offset + 4, offset + 6);
        const h = data.toString("utf8", offset + 6, offset + 8);
        const M = data.toString("utf8", offset + 8, offset + 10);

        let tz!: string;
        let s: string = "00";

        switch (length) {
        case 11:
        case 15:
            tz = data.toString("utf8", offset + 10, offset + length);
            break;
        case 13:
        case 17:
            tz = data.toString("utf8", offset + 12, offset + length);
            s = data.toString("utf8", offset + 10, offset + 12);
            break;
        }

        return [offset + length, {
            tag,
            data: new Date(`${y}-${m}-${d}T${h}:${M}:${s}${tz}`)
        }];
    }

    private _decodeBitString(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        return [offset + length, {
            tag,
            data: {
                appended: data[offset],
                value: data.slice(offset + 1, offset + length)
            }
        }];
    }

    private _decodeBoolean(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        [offset] = this._readLength(data, offset);

        return [offset + 1, {
            tag,
            data: data[offset] !== 0xFF
        }];
    }

    private _decodeRawData(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        return [offset + length, {
            tag,
            data: data.slice(offset, offset + length)
        }];
    }

    private _decodePrintableString(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        return [offset + length, {
            tag,
            data: data.toString("utf8", offset, offset + length)
        }];
    }

    private _decodeOID(tag: C.ITag, data: Buffer, offset: number): [number, C.IElement] {

        let length: number;

        [offset, length] = this._readLength(data, offset);

        const values: number[] = [];

        let d = data.slice(offset, offset + length);

        values.push(Math.floor(d[0] / 40));
        values.push(d[0] % 40);

        for (let c = 0, i = 1; i < length; i++) {

            let b = d[i];

            if (b & 0x80) {

                c = (c << 7) + (b & 0x7F);
            }
            else {

                values.push((c << 7) + b);
                c = 0;
            }
        }

        return [offset + length, {
            tag,
            data: values.join(".")
        }];
    }

    public _readTag(data: Buffer, offset: number): [number, C.ITag] {

        let type = data[offset] & 31;

        if (type !== 31) {

            return [offset + 1, {
                type,
                class: data[offset] >> 6,
                constructed: !!(data[offset] & 32)
            }];
        }
        else {

            type = 0;

            let o = offset + 1;

            for (; o < data.length; o++) {

                if (data[o] & 0x80) {

                    type = type * 0x100 + (data[o] & 0x7F);
                }
                else {

                    type = type * 0x100 + data[o];
                    break;
                }
            }

            if (o === data.length) {

                throw new Error("Unexpected ending while reading tag type.");
            }

            return [o + 1, {
                type,
                class: data[offset] >> 6,
                constructed: !!(data[offset] & 32)
            }];
        }
    }

    public _readLength(data: Buffer, offset: number): [number, number] {

        if (data[offset] === 0x80) {

            throw new Error(`Unlimited length definition is not supported yet.`);
        }

        if (data[offset] < 0x80) {

            return [offset + 1, data[offset]];
        }

        let lenBytes = 0x7F & data[offset];

        if (lenBytes + offset >= data.length) {

            throw new Error("Unexpected ending while reading tag length.");
        }

        let o = offset + 1;
        let len = 0;

        lenBytes += offset;

        for (; o <= lenBytes; o++) {

            len = len * 0x100 + data[o];
        }

        return [lenBytes + 1, len];
    }
}

export function createDecoder(): C.IDecoder {

    return new Decoder();
}
