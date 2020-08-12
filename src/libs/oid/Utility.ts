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

import * as O from './OID';

/**
 * Translate an OID to its readable name.
 *
 * @param oid The OID to be translated.
 */
export function oid2Name(oid: string): string {

    return O.OID_TO_NAME[oid] || oid;
}

/**
 * Translate an OID from its readable name.
 *
 * @param oid The readable name of an OID.
 */
export function name2OID(name: string): string | null {

    return O.OID_FROM_NAME[name] || null;
}
