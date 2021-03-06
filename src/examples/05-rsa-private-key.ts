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

// tslint:disable:no-console

import * as libsni from '../libs';
import * as fs from 'fs';

const dpriv = libsni.rsa.createPrivateKeyDecoder();

const priv = dpriv.decode(fs.readFileSync(
    `${__dirname}/../test/certs/b.local.org/key.pem`
));

console.log(JSON.stringify(priv, function(k, v): any {
    if (typeof v === 'object' && v !== null && 'data' in v && v.type === 'Buffer') {

        return Buffer.from(v.data).toString('base64');
    }
    return v;
}, 2));
