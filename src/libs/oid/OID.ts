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

export const X509_EXT_KEY_USAGE = "2.5.29.15";

export const X509_EXT_SUBJ_ALTER_NAMES = "2.5.29.17";

export const X509_EXT_EX_KEY_USAGE = "2.5.29.37";

export const X509_EXT_BASIC_CONSTRAINTS = "2.5.29.19";

export const X509_EXT_SUBJ_IDENTIFIER = "2.5.29.14";

export const OID_TO_NAME: Record<string, string> = {

    "1.3.6.1.4.1.11129.2.4.2": "Certificate Transparency",
    "1.2.840.113549.1.1.1": "RSA Encryption",
    "1.2.840.113549.1.1.2": "MD2 With RSA Encryption",
    "1.2.840.113549.1.1.3": "MD4 With RSA Encryption",
    "1.2.840.113549.1.1.4": "MD5 With RSA Encryption",
    "1.2.840.113549.1.1.5": "SHA-1 With RSA Encryption",
    "1.2.840.113549.1.1.6": "RSA-OAEP Encryption SET",
    "1.2.840.113549.1.1.7": "RSAES-OAEP",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.113549.1.1.11": "SHA-256 With RSA Encryption",
    "2.5.4.0": "Object Class",
    "2.5.4.1": "Aliased Entry Name",
    "2.5.4.2": "Knowledge Information",
    "2.5.4.3": "Common Name",
    "2.5.4.4": "Surname",
    "2.5.4.5": "SerialNumber",
    "2.5.4.6": "Country Name",
    "2.5.4.7": "Locality Name",
    "2.5.4.8": "State Or Province Name",
    "2.5.4.9": "Street Address",
    "2.5.4.10": "Organization Name",
    "2.5.4.11": "Organizational Unit Name",
    "2.5.4.12": "Title",
    "2.5.4.13": "Description",
    "2.5.4.14": "Search Guide",
    "2.5.4.15": "Business Category",
    "2.5.4.16": "Postal Address",
    "2.5.4.17": "Postal Code",
    "2.5.4.18": "Post Office Box",
    "2.5.4.19": "Physical Delivery Office Name",
    "2.5.4.20": "Telephone Number",
    "2.5.4.21": "Telex Number",
    "2.5.4.22": "Teletex Terminal Identifier",
    "2.5.4.23": "Facsimile Telephone Number",
    "2.5.4.24": "X.121 Address",
    "2.5.4.25": "International ISDN Number",
    "2.5.4.26": "Registered Address",
    "2.5.4.27": "Destination Indicator",
    "2.5.4.28": "Preferred Delivery Method",
    "2.5.4.29": "Presentation Address",
    "2.5.4.30": "Supported Application Context",
    "2.5.4.31": "Member",
    "2.5.4.32": "Owner",
    "2.5.4.33": "Role Occupant",
    "2.5.4.34": "See Also",
    "2.5.4.35": "User Password",
    "2.5.4.36": "User Certificate",
    "2.5.4.37": "CA Certificate",
    "2.5.4.38": "Authority Revocation List",
    "2.5.4.39": "Certificate Revocation List",
    "2.5.4.40": "Cross Certificate Pair",
    "2.5.4.41": "Name",
    "2.5.4.42": "Given Name",
    "2.5.4.43": "Initials",
    "2.5.4.44": "Generation Qualifier",
    "2.5.4.45": "Unique Identifier",
    "2.5.4.46": "DN Qualifier",
    "2.5.4.47": "Enhanced Search Guide",
    "2.5.4.48": "Protocol Information",
    "2.5.4.49": "Distinguished Name",
    "2.5.4.50": "Unique Member",
    "2.5.4.51": "House Identifier",
    "2.5.4.52": "Supported Algorithms",
    "2.5.4.53": "Delta Revocation List",
    "2.5.4.58": "Attribute Certificate attribute",
    "2.5.4.65": "Pseudonym",
    "2.5.29.1": "Old Authority Key Identifier",
    "2.5.29.2": "Old Primary Key Attributes",
    "2.5.29.3": "Certificate Policies",
    "2.5.29.4": "Primary Key Usage Restriction",
    "2.5.29.9": "Subject Directory Attributes",
    [X509_EXT_SUBJ_IDENTIFIER]: "Subject Key Identifier",
    [X509_EXT_KEY_USAGE]: "Key Usage",
    "2.5.29.16": "Private Key Usage Period",
    [X509_EXT_SUBJ_ALTER_NAMES]: "Subject Alternative Name",
    "2.5.29.18": "Issuer Alternative Name",
    [X509_EXT_BASIC_CONSTRAINTS]: "Basic Constraints",
    "2.5.29.20": "CRL Number",
    "2.5.29.21": "Reason code",
    "2.5.29.23": "Hold Instruction Code",
    "2.5.29.24": "Invalidity Date",
    "2.5.29.27": "Delta CRL indicator",
    "2.5.29.28": "Issuing Distribution Point",
    "2.5.29.29": "Certificate Issuer",
    "2.5.29.30": "Name Constraints",
    "2.5.29.31": "CRL Distribution Points",
    "2.5.29.32": "Certificate Policies",
    "2.5.29.33": "Policy Mappings",
    "2.5.29.35": "Authority Key Identifier",
    "2.5.29.36": "Policy Constraints",
    [X509_EXT_EX_KEY_USAGE]: "Extended key usage",
    "2.5.29.46": "Freshest CRL",
    "2.5.29.54": "X.509 v3 Extension",
    "1.3.6.1.5.5.7.1.1": "Authority Info Access"
};

export const OID_FROM_NAME: Record<string, string> = (function() {

    const ret: Record<string, string> = {};

    for (let oid in OID_TO_NAME) {

        ret[OID_TO_NAME[oid]] = oid;
    }

    return ret;
})();
