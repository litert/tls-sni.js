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

import * as Core from '@litert/core';

// eslint-disable-next-line @typescript-eslint/naming-convention
export const ErrorHub = Core.createErrorHub('@litert/tls-sni');

export const E_NO_CERT = ErrorHub.define(
    null,
    'E_NO_CERT',
    'The certificate of specific name doesn\'t exists.',
    {}
);

export const E_UNKNOWN_SERVER_NAME = ErrorHub.define(
    null,
    'E_UNKNOWN_SERVER_NAME',
    'The server name is not allowed.',
    {}
);

export const E_UNEXPECTED_ENDING = ErrorHub.define(
    null,
    'E_UNEXPECTED_ENDING',
    'Unexpected ending of content was found.',
    {}
);

export const E_INVALID_X509 = ErrorHub.define(
    null,
    'E_INVALID_X509',
    'Invalid X.509 certificate.',
    {}
);

export const E_UNSUPPORTED_BER_FEATURE = ErrorHub.define(
    null,
    'E_NOT_SUPPORTED_BER_FEATURE',
    'Unsupported BER feature was found.',
    {}
);

export const E_INVALID_WILDCARD = ErrorHub.define(
    null,
    'E_INVALID_WILDCARD',
    'Invalid wildcard subject in certificate.',
    {}
);

export const E_INVALID_RSA_KEY = ErrorHub.define(
    null,
    'E_INVALID_RSA_KEY',
    'Invalid RSA key file.',
    {}
);
