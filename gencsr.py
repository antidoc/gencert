#!/usr/bin/env python3
from OpenSSL import crypto
import sys
from config import org_fields


with open ('ca.crt', 'r') as file:
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())

with open ('ca.key', 'r') as file:
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())

of = org_fields()

def make_key():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)
    return pkey


def make_csr(pkey, cn, email=of.email, C=of.C, ST=of.ST, L=of.L, OU=of.OU, hashalgorithm='sha256WithRSAEncryption'):
    req = crypto.X509Req()
    req.get_subject().CN = cn
    req.get_subject().C = C
    req.get_subject().ST = ST
    req.get_subject().L = L
    req.get_subject().OU = OU
    req.get_subject().emailAddress = email
    req.set_pubkey(pkey)
    req.sign(pkey, hashalgorithm)
    return req


def create_new_certificate(csr, cakey, cacert, serial):
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*60*24*365*10)
    cert.set_issuer(cacert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_version(2)

    extensions = []
    extensions.append(crypto.X509Extension(b'basicConstraints', False ,b'CA:FALSE'))

    extensions.append(crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert))
    extensions.append(crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always,issuer:always', subject=cacert, issuer=cacert))

    cert.add_extensions(extensions)
    cert.sign(cakey, 'sha256WithRSAEncryption')

    return cert

def main(cacert, cakey, username, serial):
    key = make_key()
    csr = make_csr(key, username)
    crt = create_new_certificate(csr, cakey, cacert, serial)
    sys.stdout.buffer.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    sys.stdout.buffer.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr))
    sys.stdout.buffer.write(crypto.dump_certificate(crypto.FILETYPE_PEM, crt))

main(cacert, cakey, 'shaman', 0x0C)
