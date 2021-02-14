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

export const X509_EXT_KEY_USAGE = '2.5.29.15';

export const X509_EXT_SUBJ_ALTER_NAMES = '2.5.29.17';

export const X509_EXT_EX_KEY_USAGE = '2.5.29.37';

export const X509_EXT_BASIC_CONSTRAINTS = '2.5.29.19';

export const X509_EXT_SUBJ_IDENTIFIER = '2.5.29.14';

export const OID_TO_NAME: Record<string, string> = {

    /**
     * EC OIDs BEGIN {
     *
     * @see https://tools.ietf.org/html/rfc5480#section-2.1.1.1
     */
    '1.2.840.10045.3.1.1': 'secp192r1/ansip192r1/ansiX9p192r1/prime192v1/P-192',
    '1.2.840.10045.3.1.7': 'secp256r1/ansip256r1/ansiX9p256r1/prime256v1/P-256',
    '1.3.132.0.1': 'sect163k1/ansit163k1/ansiX9t163k1',
    '1.3.132.0.2': 'sect163r1/ansit163r1/ansiX9t163r1',
    '1.3.132.0.3': 'sect239k1/ansit239k1/ansiX9t239k1',
    '1.3.132.0.8': 'secp160r1/ansip160r1/ansiX9p160r1/prime160v1/P-160',
    '1.3.132.0.9': 'secp160k1/ansip160k1/ansiX9p160k1',
    '1.3.132.0.10': 'secp256k1/ansip256k1/ansiX9p256k1',
    '1.3.132.0.15': 'sect163r2/ansit163r2/ansiX9t163r2',
    '1.3.132.0.16': 'sect283k1/ansit283k1/ansiX9t283k1',
    '1.3.132.0.17': 'sect283r1/ansit283r1/ansiX9t283r1',
    '1.3.132.0.24': 'sect193r1/ansit193r1/ansiX9t193r1',
    '1.3.132.0.25': 'sect193r2/ansit193r2/ansiX9t193r2',
    '1.3.132.0.26': 'sect233k1/ansit233k1/ansiX9t233k1',
    '1.3.132.0.27': 'sect233r1/ansit233r1/ansiX9t233r1',
    '1.3.132.0.30': 'secp160r2/ansip160r2/ansiX9p160r2',
    '1.3.132.0.31': 'secp192k1/ansip192k1/ansiX9p192k1',
    '1.3.132.0.32': 'secp224k1/ansip224k1/ansiX9p224k1',
    '1.3.132.0.33': 'secp224r1/ansip224r1/ansiX9p224r1/prime224v1/P-224',
    '1.3.132.0.34': 'secp384r1/ansip384r1/ansiX9p384r1/prime384v1/P-384',
    '1.3.132.0.35': 'secp521r1/ansip521r1/ansiX9p521r1/prime521v1/P-521',
    '1.3.132.0.36': 'sect409k1/ansit409k1/ansiX9t409k1',
    '1.3.132.0.37': 'sect409r1/ansit409r1/ansiX9t409r1',
    '1.3.132.0.38': 'sect571k1/ansit571k1/ansiX9t571k1',
    '1.3.132.0.39': 'sect571r1/ansit571r1/ansiX9t571r1',
    '1.2.840.10045.2.1': 'ecPublicKey',
    /**
     * } // EC OIDs END
     */
    '1.3.6.1.4.1.11129.2.4.2': 'Certificate Transparency',
    '1.2.840.113549.1.1.1': 'RSA Encryption',
    '1.2.840.113549.1.1.2': 'MD2 With RSA Encryption',
    '1.2.840.113549.1.1.3': 'MD4 With RSA Encryption',
    '1.2.840.113549.1.1.4': 'MD5 With RSA Encryption',
    '1.2.840.113549.1.1.5': 'SHA-1 With RSA Encryption',
    '1.2.840.113549.1.1.6': 'RSA-OAEP Encryption SET',
    '1.2.840.113549.1.1.7': 'RSAES-OAEP',
    '1.2.840.113549.1.1.10': 'RSASSA-PSS',
    '1.2.840.113549.1.1.11': 'SHA-256 With RSA Encryption',
    '2.5.4.0': 'Object Class',
    '2.5.4.1': 'Aliased Entry Name',
    '2.5.4.2': 'Knowledge Information',
    '2.5.4.3': 'Common Name',
    '2.5.4.4': 'Surname',
    '2.5.4.5': 'SerialNumber',
    '2.5.4.6': 'Country Name',
    '2.5.4.7': 'Locality Name',
    '2.5.4.8': 'State Or Province Name',
    '2.5.4.9': 'Street Address',
    '2.5.4.10': 'Organization Name',
    '2.5.4.11': 'Organizational Unit Name',
    '2.5.4.12': 'Title',
    '2.5.4.13': 'Description',
    '2.5.4.14': 'Search Guide',
    '2.5.4.15': 'Business Category',
    '2.5.4.16': 'Postal Address',
    '2.5.4.17': 'Postal Code',
    '2.5.4.18': 'Post Office Box',
    '2.5.4.19': 'Physical Delivery Office Name',
    '2.5.4.20': 'Telephone Number',
    '2.5.4.21': 'Telex Number',
    '2.5.4.22': 'Teletex Terminal Identifier',
    '2.5.4.23': 'Facsimile Telephone Number',
    '2.5.4.24': 'X.121 Address',
    '2.5.4.25': 'International ISDN Number',
    '2.5.4.26': 'Registered Address',
    '2.5.4.27': 'Destination Indicator',
    '2.5.4.28': 'Preferred Delivery Method',
    '2.5.4.29': 'Presentation Address',
    '2.5.4.30': 'Supported Application Context',
    '2.5.4.31': 'Member',
    '2.5.4.32': 'Owner',
    '2.5.4.33': 'Role Occupant',
    '2.5.4.34': 'See Also',
    '2.5.4.35': 'User Password',
    '2.5.4.36': 'User Certificate',
    '2.5.4.37': 'CA Certificate',
    '2.5.4.38': 'Authority Revocation List',
    '2.5.4.39': 'Certificate Revocation List',
    '2.5.4.40': 'Cross Certificate Pair',
    '2.5.4.41': 'Name',
    '2.5.4.42': 'Given Name',
    '2.5.4.43': 'Initials',
    '2.5.4.44': 'Generation Qualifier',
    '2.5.4.45': 'Unique Identifier',
    '2.5.4.46': 'DN Qualifier',
    '2.5.4.47': 'Enhanced Search Guide',
    '2.5.4.48': 'Protocol Information',
    '2.5.4.49': 'Distinguished Name',
    '2.5.4.50': 'Unique Member',
    '2.5.4.51': 'House Identifier',
    '2.5.4.52': 'Supported Algorithms',
    '2.5.4.53': 'Delta Revocation List',
    '2.5.4.58': 'Attribute Certificate attribute',
    '2.5.4.65': 'Pseudonym',
    '2.5.29.1': 'Old Authority Key Identifier',
    '2.5.29.2': 'Old Primary Key Attributes',
    '2.5.29.3': 'Certificate Policies',
    '2.5.29.4': 'Primary Key Usage Restriction',
    '2.5.29.9': 'Subject Directory Attributes',
    [X509_EXT_SUBJ_IDENTIFIER]: 'Subject Key Identifier',
    [X509_EXT_KEY_USAGE]: 'Key Usage',
    '2.5.29.16': 'Private Key Usage Period',
    [X509_EXT_SUBJ_ALTER_NAMES]: 'Subject Alternative Name',
    '2.5.29.18': 'Issuer Alternative Name',
    [X509_EXT_BASIC_CONSTRAINTS]: 'Basic Constraints',
    '2.5.29.20': 'CRL Number',
    '2.5.29.21': 'Reason code',
    '2.5.29.23': 'Hold Instruction Code',
    '2.5.29.24': 'Invalidity Date',
    '2.5.29.27': 'Delta CRL indicator',
    '2.5.29.28': 'Issuing Distribution Point',
    '2.5.29.29': 'Certificate Issuer',
    '2.5.29.30': 'Name Constraints',
    '2.5.29.31': 'CRL Distribution Points',
    '2.5.29.32': 'Certificate Policies',
    '2.5.29.33': 'Policy Mappings',
    '2.5.29.35': 'Authority Key Identifier',
    '2.5.29.36': 'Policy Constraints',
    [X509_EXT_EX_KEY_USAGE]: 'Extended key usage',
    '2.5.29.46': 'Freshest CRL',
    '2.5.29.54': 'X.509 v3 Extension',
    '1.3.6.1.5.5.7.1.1': 'Authority Info Access'
};

export const OID_FROM_NAME: Record<string, string> = (function() {

    const ret: Record<string, string> = {};

    for (let oid in OID_TO_NAME) {

        ret[OID_TO_NAME[oid]] = oid;
    }

    return ret;
})();
