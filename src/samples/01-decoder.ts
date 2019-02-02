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

// tslint:disable:no-console

import * as SNI from "../libs";
import * as FS from "fs";

const TEST_CERT = FS.readFileSync(
    __dirname + "/../test/sample.crt"
);

const der = SNI.der.createDecoder();

const x509 = SNI.x509.createDecoder();

SNI.der.print(
    der.decode(x509.pem2DER(TEST_CERT)),
    function(text, depth): void {

        console.log("  ".repeat(depth) + text);
    }
);

const ret = x509.decode(TEST_CERT);

console.log(JSON.stringify(ret, function(k, v): any {
    if (typeof v === "object" && v !== null && "data" in v && v.type === "Buffer") {

        return Buffer.from(v.data).toString("base64");
    }
    return v;
}, 2));
