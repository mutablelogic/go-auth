// PEM encoding of the API's certificates and private keys, which are their
// DER encodings, in base64, so they can be saved as files

import type { CertBundle, Certificate } from './schema.ts';

// pem encodes base64 DER as a PEM block of the type, in lines of 64
export function pem(type: string, base64: string): string {
    const body = base64.replace(/\s+/g, '').match(/.{1,64}/g)?.join('\n') ?? '';
    return `-----BEGIN ${type}-----\n${body}\n-----END ${type}-----\n`;
}

// certificatePEM is a certificate, and its issuers, up to the root, when the
// bundle has them, as PEM, which is what a server presents
export function certificatePEM(bundle: CertBundle): string {
    return [bundle, ...(bundle.chain ?? [])]
        .filter((cert: Certificate) => cert.cert)
        .map((cert: Certificate) => pem('CERTIFICATE', cert.cert!))
        .join('');
}

// privateKeyPEM is a bundle's private key, as PEM
export function privateKeyPEM(bundle: CertBundle): string {
    if (!bundle.key) {
        throw new Error(`${bundle.name} has no private key`);
    }
    return pem('PRIVATE KEY', bundle.key);
}

// download saves the text as a file, with the name
export function download(filename: string, text: string, type = 'application/x-pem-file'): void {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}
