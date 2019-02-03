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

import * as libsni from "../libs";
import * as FS from "fs";

const cm = libsni.certs.createManager();

for (const name of ["a.local.org", "b.local.org", "x.local.org"]) {

    cm.use(
        name,
        FS.readFileSync(`${__dirname}/../test/certs/${name}/fullchain.pem`),
        FS.readFileSync(`${__dirname}/../test/certs/${name}/key.pem`)
    );
}

for (const hostname of [
    "a.local.org",
    "b.local.org",
    "c.local.org",
    "x.local.org",
    "local.org",
    "g.local.org",
    "dddd.local.org"
]) {

    const result = cm.test(hostname);

    if (result !== null) {

        console.info(`Hostname ${hostname.padEnd(20)} Use "${result}".`);
    }
    else {

        console.error(`Hostname ${hostname.padEnd(20)} NOT FOUND.`);
    }
}
