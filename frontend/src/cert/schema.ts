// The certificate API's types, as go-auth's cert package has them

// CertKey is a certificate's version: its name, and its serial number, in
// decimal
export interface CertKey {
    name: string;
    serial: string;
}

// SubjectMeta is a certificate's subject, other than its common name, which
// is its name
export interface SubjectMeta {
    organizationName?: string;
    organizationalUnit?: string;
    countryName?: string;
    localityName?: string;
    stateOrProvinceName?: string;
    streetAddress?: string;
    postalCode?: string;
}

// SubjectRef is a stored certificate's subject, by its identifier, with its
// common name, and the whole subject as a distinguished name
export interface SubjectRef extends SubjectMeta {
    id?: number;
    commonName?: string;
    name?: string;
}

// Subject is a stored subject, which certificates share, with the number of
// certificates which use it: one which none uses can be changed or deleted.
// subject is its fields as a distinguished name.
export interface Subject extends SubjectMeta {
    id: number;
    timestamp?: string;
    subject?: string;
    certs: number;
}

// SubjectList is a page of subjects, in the order they were created
export interface SubjectList {
    count: number;
    offset?: number;
    limit?: number;
    body?: Subject[];
}

// Certificate is a stored certificate, without its private key. cert is its
// DER encoding, in base64.
export interface Certificate extends CertKey {
    signer?: CertKey;
    subject?: SubjectRef;
    san?: string[];
    not_before?: string;
    not_after?: string;
    is_ca?: boolean;
    enabled?: boolean;
    tags?: string[];
    effective_tags?: string[];
    cert?: string;
    timestamp?: string;
}

// CertBundle is a certificate, with its issuers, up to the root, when
// they're asked for, and its private key, when it's asked for, as its PKCS
// #8 DER encoding, in base64
export interface CertBundle extends Certificate {
    chain?: Certificate[];
    key?: string;
}

// CertList is a page of certificates, other than the root, in name order,
// and the latest version of each name first
export interface CertList {
    count: number;
    offset?: number;
    limit?: number;
    body?: Certificate[];
}

// CertListRequest filters, and pages, the certificates
export interface CertListRequest {
    offset?: number;
    limit?: number;
    is_ca?: boolean;
    enabled?: boolean;
    valid?: boolean;
    tags?: string[];
    // latest is each certificate's latest version, when it's true, or its
    // older versions, when it's false, and name is a certificate's versions
    latest?: boolean;
    name?: string;
    // search is the certificates whose names have its text, in any case
    search?: string;
    // sort is the column they're sorted by, in the order, ascending unless
    // it's desc, rather than by name, then each name's versions, the latest
    // first
    sort?: CertSort;
    order?: 'asc' | 'desc';
}

// CertSort is a column which certificates are sorted by
export type CertSort = 'name' | 'signer' | 'expires';

// CreateCertRequest creates a certificate authority, or a certificate.
// expiry is in nanoseconds, as Go's durations are, and the server's default
// when it's not set.
export interface CreateCertRequest {
    name: string;
    expiry?: number;
    subject?: SubjectMeta;
    san?: string[];
    tags?: string[];
}

// RenewCertRequest renews a certificate, keeping its lifetime and subject
// when they're not set
export interface RenewCertRequest {
    expiry?: number;
    subject?: SubjectMeta;
}

// CertMeta is what can be changed of a stored certificate: whether it's
// enabled, and its tags, which are removed when they're empty
export interface CertMeta {
    enabled?: boolean;
    tags?: string[];
}

// CertFeatures is what the server's certificate manager can do, from its
// configuration's cert section, without which the server has no
// certificates: whether a root is stored, without which certificate
// authorities can't be created
export interface CertFeatures {
    root: boolean;
}

// RootCertName is the root certificate's name
export const RootCertName = '$root$';

// NamePattern is what a certificate's name, or a tag, is: a letter, then up
// to 63 letters, digits, underscores and hyphens
export const NamePattern = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;

// Day is a day, in nanoseconds, as the API's expiries are
export const Day = 24 * 60 * 60 * 1e9;

// certType is what the certificate is
export function certType(cert: Certificate): 'root' | 'ca' | 'certificate' {
    if (cert.name === RootCertName) {
        return 'root';
    }
    return cert.is_ca ? 'ca' : 'certificate';
}

// certExpired is true when the certificate's validity has ended, at the time
export function certExpired(cert: Certificate, now = Date.now()): boolean {
    return !!cert.not_after && Date.parse(cert.not_after) <= now;
}

// CertValidity is whether a certificate is valid at a time, has expired, or
// isn't valid yet
export type CertValidity = 'valid' | 'expired' | 'pending';

// certValidity is whether the certificate is valid at the time, between its
// not_before and not_after, or has expired, or isn't valid yet
export function certValidity(cert: Certificate, now = Date.now()): CertValidity {
    if (certExpired(cert, now)) {
        return 'expired';
    }
    if (cert.not_before && Date.parse(cert.not_before) > now) {
        return 'pending';
    }
    return 'valid';
}
