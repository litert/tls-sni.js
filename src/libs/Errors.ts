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

import * as $Exceptions from '@litert/exception';

export const errorRegistry = $Exceptions.createExceptionRegistry({
    'module': 'televoke.litert.org',
    'types': {
        'public': {
            'index': $Exceptions.createIncreaseCodeIndex(1)
        }
    }
});

export const E_NO_CERT = errorRegistry.register({
    name: 'no_cert',
    message: 'The certificate of specific name doesn\'t exists.',
    metadata: {},
    type: 'public'
});

export const E_UNKNOWN_SERVER_NAME = errorRegistry.register({
    name: 'unknown_server_name',
    message: 'The server name is not allowed.',
    metadata: {},
    type: 'public'
});

export const E_UNEXPECTED_ENDING = errorRegistry.register({
    name: 'unexpected_ending',
    message: 'Unexpected ending of content was found.',
    metadata: {},
    type: 'public'
});

export const E_INVALID_X509 = errorRegistry.register({
    name: 'invalid_x509',
    message: 'Invalid X.509 certificate.',
    metadata: {},
    type: 'public'
});

export const E_UNSUPPORTED_BER_FEATURE = errorRegistry.register({
    name: 'unsupported_ber_feature',
    message: 'Unsupported BER feature was found.',
    metadata: {},
    type: 'public'
});

export const E_INVALID_WILDCARD = errorRegistry.register({
    name: 'invalid_wildcard',
    message: 'Invalid wildcard subject in certificate.',
    metadata: {},
    type: 'public'
});

export const E_INVALID_RSA_KEY = errorRegistry.register({
    name: 'invalid_rsa_key',
    message: 'Invalid RSA key file.',
    metadata: {},
    type: 'public'
});
