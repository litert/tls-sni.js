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

function printDERStruct(
    e: C.IElement,
    printer: (text: any, depth: number) => void,
    depth: number
): void {

    if (e.tag.class !== C.ETClass.UNIVERSAL) {

        printer(`+ ${C.ETClass[e.tag.class]}.${e.tag.type}`, depth);

        if (e.tag.constructed) {

            printDERStruct(e.data, printer, depth + 1);
        }
        else {

            printer(e.data, depth + 1);
        }

        return;
    }

    printer(`+ ${C.ETClass[e.tag.class]}.${C.ETKind[e.tag.type]}`, depth);

    if (Array.isArray(e.data)) {

        for (let x of e.data) {

            printDERStruct(x, printer, depth + 1);
        }
    }
    else if (e.data instanceof Buffer) {

        printer(e.data.toString('hex'), depth + 1);
    }
    else {

        if (typeof e.data === 'object' && e.data !== null && 'tag' in e.data) {

            printDERStruct(e.data, printer, depth + 2);
        }
        else {

            printer(JSON.stringify(e.data), depth + 1);
        }
    }
}

/**
 * Print the decoded DER data.
 * @param data      The data to be printed.
 * @param printer   The callback to print the text.
 */
export function print(
    data: C.IElement,
    printer: (text: any, depth: number) => void
): void {

    printDERStruct(data, printer, 0);
}
