# -*- coding: utf-8 -*-
#! /usr/bin/env python3
"""
A script to convert a zipped application file to a MIME package and sign it according to ATSC A/360:2021

Usage:   python3 Tools/scripts/dtv_app_sign.py -app_file APPLICATION.zip -package_file APPLICATION.multipart -author_certs author-certs.p12 -distributor_certs distributor-certs.p12 -pswd password
"""

import argparse
import os.path
import zipfile
import fnmatch
# For guessing MIME type based on file name extension
import mimetypes

from email import encoders
from email.message import Message
from email.mime.text import MIMEText
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

import xml.etree.ElementTree as etree
from xml.dom import minidom
from pathlib import Path
import base64
import ssl

from M2Crypto import BIO, Rand, SMIME
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPResponseStatus
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
backend = default_backend()


#######################
# SUBROUTINES
#######################

def process_certs(certificates: str, password: str):
    with open(certificates, 'rb') as pkcs12_file:
        pkcs12_auth = pkcs12_file.read()
    caP12 = load_key_and_certificates(pkcs12_auth, password.encode('utf-8'), backend)
    #print(aucaP12[2][1])
    priv_key = caP12[0].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    priv_cert = caP12[1].public_bytes(Encoding.PEM)
    signing_cert = caP12[2][0].public_bytes(Encoding.PEM)
    root_cert = caP12[2][1].public_bytes(Encoding.PEM)
    
    return caP12

def get_ocsp_server(cert):
    aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    ocsps = [ia for ia in aia if ia.access_method == AuthorityInformationAccessOID.OCSP]
    if not ocsps:
        raise Exception(f'no ocsp server entry in AIA')
    return ocsps[0].access_location.value

def readzip(source_file: str, dest_file: str, imageList: list):
    """
    Extract the name of the file, information list showing directory structure and filenames
    
    Parameters
    ----------
    source_file
        The path to the source file to be read
    
    Returns
    -------
        The information
    """
    
    # create the file structure
    metadataEnvelope = etree.Element('metadataEnvelope')
    metadataEnvelope.set('xmlns','urn:3gpp:metadata:2005:MBMS:envelope')
    # Unzip the file
    with zipfile.ZipFile(source_file, 'r') as inzip:
        inzip.extractall("./")
    #print(inzip.namelist())
    #print(inzip.infolist())
    #print(inzip.filename)
    #print(os.stat(source_file).st_size)
    #print(inzip.printdir())
    for info in inzip.infolist():
    #    print(info.filename)
    #    print('\tComment:\t', info.comment)
    #    print('\tModified:\t', datetime.datetime(*info.date_time))
    #    print('\tSystem:\t\t', info.create_system, '(0 = Windows, 3 = Unix)')
    #    print('\tZIP version:\t', info.create_version)
    #    print('\tCompressed:\t', info.compress_size, 'bytes')
    #    print('\tUncompressed:\t', info.file_size, 'bytes')
        ctype, encoding = mimetypes.guess_type(info.filename)
        #if not a real file or not a MACOSX directory file, don't include
        if not os.path.isfile(info.filename) or fnmatch.fnmatch(os.path.basename(info.filename),'._*'):
            #print(info.filename, 'This is an empty directory')
            continue
        if ctype is None or encoding is not None:
            #print('.DS_store binary data')
            ctype='application/octet-stream'
            continue
        # Create one Element of item for each file
        item = etree.SubElement(metadataEnvelope, 'item')
        # Fill in the Element item with 4 Attributes
        item.set('metadataURI',info.filename)
        item.set('version',str(0))
        item.set('contentType',ctype)
        item.set('contentLength',str(info.file_size))
        #item.tail='\r'
        #etree.dump(item)
    
    # create a new XML file with the results
    #mydata = etree.tostring(metadataEnvelope, encoding="utf-8")
    mydata = minidom.parseString(etree.tostring(metadataEnvelope)).toprettyxml(encoding="UTF-8", indent="    ")
    #with open("envelope.xml", "w") as myfile:
    #    myfile.write(mydata.encode('utf-8'))
    
    # Create the enclosing (outer) message
    outer = MIMEMultipart('related')
    del(outer['mime-version'])
    outer.preamble = 'You will not see this in a MIME-aware mail reader.\n'
    
    # Create the envelope
    part = MIMEApplication(mydata, _subtype='mbms-envelope+xml', _encoder=encoders.encode_noop)
    part.add_header('Content-Location', 'envelope.xml')
    del(part['mime-version'])
    outer.attach(part)
    
    # Create the separate files
    for info in inzip.infolist():
        file = info.filename
        ctype, encoding = mimetypes.guess_type(file)
        #if not a real file or not a MACOSX directory file, don't include
        if not os.path.isfile(file) or fnmatch.fnmatch(os.path.basename(file),'._*'):
            continue
        if ctype is None or encoding is not None:
            # No guess could be made, or the file is encoded (compressed), so
            # use a generic bag-of-bits type.
            ctype = 'application/octet-stream'
            continue
        maintype, subtype = ctype.split('/', 1)
        if maintype == 'text':
            with open(file) as fp:
                # Note: we should handle calculating the charset
                msg = MIMEText(fp.read(), _subtype=subtype)
                #msg = MIMEText(fp.read(), _subtype=subtype, policy=outer.policy.clone(linesep='\r\n'))
        elif maintype == 'image':
            msg = MIMEBase("image", _subtype=subtype)
            msg.add_header( 'Content-Transfer-Encoding', 'binary' )
            # Only keep these headers as markers to fill in the image files later.
            # Record a list of images
            imageList.append(file)
        elif maintype == 'audio':
            with open(file, 'rb') as fp:
                msg = MIMEAudio(fp.read(), _subtype=subtype)
        else:
            with open(file, 'rb') as fp:
                msg = MIMEBase(maintype, subtype)
                msg.set_payload(fp.read())
            msg.add_header( 'Content-Transfer-Encoding', 'binary' )
            #print(info.filename, 'This is not text, image or audio file')
        # Set the filename parameter
        msg.add_header('Content-Location', file)
        del(msg['mime-version'])
        outer.attach(msg)
    # Now send or store the message
    #composed = outer.as_bytes(policy=msg.policy.clone(linesep=""))
    composed = outer.as_bytes(policy=msg.policy.clone(linesep="\r\n"))
    #composed = outer.as_bytes().replace(b'\n', b'\r\n')
    #composed = outer.as_bytes()
    
    #if args.output:
    with open(dest_file, 'wb', buffering=0) as fp:
        #gen=generator.BytesGenerator(fp)
        #gen.flatten(outer, unixfrom=True, linesep='\r\n')
        #gen.flatten(outer, unixfrom=True, linesep="")
        fp.write(composed)
    print("BINARY MIME Package structure complete, adding images")


#######################
# MAIN PROGRAM
#######################

if __name__ == "__main__":
    # Create our Argument parser and set its description
    parser = argparse.ArgumentParser(
        description="Script that converts a DOS like file to an Unix like file",
    )
    
    # Add the arguments:
    #   - app_file: the app file we want to S/MIME package and sign
    #   - package_file: the output destination where signed package should go
    
    # Note: the use of the argument type of argparse.FileType could
    # streamline some things
    parser.add_argument(
        '-app_file',
        help='The location of the zipped application file '
    )
    parser.add_argument(
        '-package_file',
        help='Location of S/MIME package output file (default: app_file appended with `_end`',
        default=None
    )
    parser.add_argument(
        '-author_certs',
        help='Location of certificates for signing S/MIME package',
        default=None
    )
    parser.add_argument(
        '-distributor_certs',
        help='Location of certificates for signing S/MIME package',
        default=None
    )
    parser.add_argument(
        '-pswd',
        help='Password to unlock the certificates file',
        default=None
    )
    
    # Parse the args (argparse automatically grabs the values from
    # sys.argv)
    args = parser.parse_args()
    
    s_file = args.app_file
    d_file = args.package_file
    ac_file = args.author_certs
    dc_file = args.distributor_certs
    p_file = args.pswd
    
    # If the destination file wasn't passed, then assume we want to
    # create a new file based on the old one
    if d_file is None:
        file_path, file_extension = os.path.splitext(s_file)
        d_file = f'{file_path}_end{file_extension}'
    
    file_path, file_extension = os.path.splitext(s_file)
    tmp_file = f'{file_path}_tmp{file_extension}'
    imageList=[]
    
    readzip(s_file, tmp_file, imageList)
    
    # Next part is extremely painful, all due to Linux or Windows messing with end of line characters
    # in the binary image files, simply upon a read.
    # Have to complete the MIME package, then search through file for images and file merge in the actual image files.
    # print(imageList)
    
    print('signing...')
    
    auca12 = process_certs(ac_file, p_file)
    with open('author_cert.pem', 'wb') as out:
        out.write(auca12[1].public_bytes(Encoding.PEM))
    with open('author_key.pem', 'wb') as out:
        out.write(auca12[0].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    
    dtca12 = process_certs(dc_file, p_file)
    with open('issuer_cert.pem', 'wb') as out:
        out.write(dtca12[2][0].public_bytes(Encoding.PEM))
    with open('root_cert.pem', 'wb') as out:
        out.write(dtca12[2][1].public_bytes(Encoding.PEM))
    with open('distrib_cert.pem', 'wb') as out:
        out.write(dtca12[1].public_bytes(Encoding.PEM))
    with open('distrib_key.pem', 'wb') as out:
        out.write(dtca12[0].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    
    # bundle the root and issuer certificates
    import subprocess
    subprocess.check_output("cat root_cert.pem issuer_cert.pem > bundle.pem", shell=True)
    
    buf = BIO.MemoryBuffer()
    
    # put message with attachments into into SSL I/O buffer
    with open(tmp_file, 'rb') as mimepkg:
        for line in mimepkg:
            buf.write(line)
            for filename in imageList:
                if (b'Content-Location:' in line) & (bytes(filename, 'utf-8') in line):
                    #imageLoc = mimepkg.tell()
                    #print(imageLoc)
                    # write one line space
                    buf.write(b'\r\n')
                    #with open(filename,'rb') as readfile:
                    #    img = Image.open(readfile, mode='r')
                    #    buf.write(image_to_byte_array(img))
                    img = Path(filename).read_bytes()
                    buf.write(img)
    
    ##############################################
    # Now have MIME Package
    # Sign that package
    ##############################################
    
    # Load seed file for PRNG
    Rand.load_file('/tmp/randpool.dat', -1)
    
    # Instantiate an SMIME object
    s = SMIME.SMIME()
    
    # load author certificate
    s.load_key('author_key.pem', 'author_cert.pem')
    
    au_cert = x509.load_pem_x509_certificate(auca12[1].public_bytes(Encoding.PEM), default_backend())
    issuer_cert = x509.load_pem_x509_certificate(auca12[2][0].public_bytes(Encoding.PEM), default_backend())
    
    ocsp_server = get_ocsp_server(au_cert)
    #print('   ocsp_server ->', ocsp_server)
    
    # We need to input a command line entry to run OpenSSL to get OCSP Responses.
    openssl_location =  "\openssl.exe"
    request_cmd = 'ocsp -issuer issuer_cert.pem -cert author_cert.pem -CAfile bundle.pem -respout author_ocsp.der -url ' + ocsp_server
    #request_cmd = 'ocsp -issuer issuer_cert.pem -cert author_cert.pem -CAfile bundle.pem -noverify -respout author_ocsp.der -url ' + ocsp_server
    #request_cmd = 'ocsp -issuer issuer_cert.pem -cert author_cert.pem -text -respout author_ocsp.der -header Host=pki-ocsp.nextgentvtrust.com -url ' + ocsp_server
    full_cmd = openssl_location + " " + request_cmd
    ocspResponse = subprocess.check_output(full_cmd, shell=True)
    with open('author_ocsp.der', 'rb') as au_resp:
        au_resp_data = au_resp.read()
    #au_ocsp = ssl.DER_cert_to_PEM_cert(au_resp_data)
    
    request_cmd = 'ocsp -issuer issuer_cert.pem -cert distrib_cert.pem -CAfile bundle.pem -respout distrib_ocsp.der -url ' + ocsp_server
    full_cmd = openssl_location + " " + request_cmd
    ocspResponse = subprocess.check_output(full_cmd, shell=True)
    with open('distrib_ocsp.der', 'rb') as dt_resp:
        dt_resp_data = dt_resp.read()
    #dt_ocsp = ssl.DER_cert_to_PEM_cert(dt_resp_data)
    
    au_ocsp_status = ocsp.load_der_ocsp_response(au_resp_data)
    dt_ocsp_status = ocsp.load_der_ocsp_response(dt_resp_data)
    #print(au_ocsp)
    #print(au_ocsp_status.certificate_status.value)
    #print(au_ocsp_status.response_status)
    #print("OCSP Request: ", full_cmd)
    #print("OCSP Response: ", ocspResponse)
    
    ##############################################
    # Now have the APP and OCSP responses for Author and Distributor certificates
    # M2Crypto library does not support OCSP responses, so use CMS library
    ##############################################    
    
    # Build a CMS structure line by line now as M2Crypto does not support OCSP Responses
    from asn1crypto import cms, util, x509, pem, ocsp
    
    sd = cms.SignedData()
    #sd = cms.SignedAndEnvelopedData()
    
    # Populating some of its field
    sd['version']='v3'
    #sd['encap_content_info']=util.OrderedDict([ ('content_type', 'data'), ('content', buf.read()) ])
    sd['encap_content_info']=util.OrderedDict([ ('content_type', 'data'), ('content', b'dummy') ])
    sd['digest_algorithms']=[ util.OrderedDict([ ('algorithm', 'sha256'), ('parameters', None) ]) ]
    
    # Getting the raw value (DER) of author certificate and storing it in x509
    #cert = x509.Certificate.load(certObj[Attribute.VALUE])
    cert = x509.Certificate.load(auca12[1].public_bytes(Encoding.DER))
    
    # Adding this certificate to SignedData object
    sd['certificates'] = [cert]
    
    # put OCSP response into CMS structure as OtherRevocationInfoFormat (OID = 1.3.6.1.5.5.7.16.2)
    # Adding Certificate Revocation List (CRL) - METHOD 1
    crlreply = ocsp.OCSPResponse()
    crlreply['response_status']=au_ocsp_status.response_status.value
    crlreply['response_bytes']=ocsp.ResponseBytes.load(au_resp_data)
    #sd['crls'] = [crlreply]
    
    # Adding Certificate Revocation List (CRL) - METHOD 2
    crlist = cms.OtherRevocationInfoFormat()
    crlist['other_rev_info_format'] = 'ocsp_response'
    crlist['other_rev_info'] = crlreply
    sd['crls'] = [crlist]
    
    # Adding Certificate Revocation List (CRL) - METHOD 3
    #ocspreply = cms.RevocationInfoChoices.load(au_resp_data, strict=False, tag=16)
    #sd['crls'] = [ocspreply]
    
    # Setting signer info section
    signer_info = cms.SignerInfo()
    #signer_info['version']=cms_version
    signer_info['version']='v3'
    signer_info['digest_algorithm']=util.OrderedDict([('algorithm', 'sha256'), ('parameters', None) ])
    signer_info['signature_algorithm']=util.OrderedDict([('algorithm', 'sha256_rsa'), ('parameters', None) ])
    
    # Creating a signature
    # write the buffer to a file to use in command line
    with open('data.txt', 'wb') as dt_file:
         dt_file.write(buf.read())
    # refill the buffer
    with open('data.txt', 'rb') as dt_file:
        for line in dt_file:
            buf.write(line)
    
    #ossl_cmd = 'cms -sign -binary -in data.txt -md sha256 -signer author_cert.pem -inkey author_key.pem -out test_data.cms -outform PEM'
    ossl_cmd = 'cms -sign -binary -in data.txt -md sha256 -signer author_cert.pem -inkey author_key.pem -outform PEM'
    sign_cmd = openssl_location + " " + ossl_cmd
    #signing = subprocess.check_output(sign_cmd, shell=True)
    signer_info['signature'] = subprocess.check_output(sign_cmd, shell=True)
    
    # Finding subject_key_identifier from certificate (asn1crypto.x509 object)
    key_id = cert.key_identifier_value.native
    signer_info['sid'] = cms.SignerIdentifier({ 'subject_key_identifier': key_id })
    #print(signer_info)
    
    # Adding SignerInfo object to SignedData object
    sd['signer_infos'] = [ signer_info ]
    
    # Writing everything into ASN.1 object
    asn1obj = cms.ContentInfo()
    asn1obj['content_type'] = 'signed_data'
    asn1obj['content'] = sd
    #print(sd)
    
    # Place the signing at the end of the buffer (DER format)
    #with open('signed_data.der','wb+') as fout:
    #    fout.write(asn1obj.dump())
    #    #fout.write(signer_info.dump())
    #buf.write(asn1obj.dump())
    #buf.write(base64.b64encode(asn1obj.dump()))
    #buf.write(base64.encodebytes(asn1obj.dump()))
    
    # Hold on to this signature with OCSP response
    au_signd = base64.encodebytes(asn1obj.dump())
    
    # sign buffer data with Author's certificate
    signed = s.sign(buf, SMIME.PKCS7_DETACHED, 'sha256')
    
    # create buffer for final package
    pkg = BIO.MemoryBuffer()
    
    # write signature into now empty buffer
    s.write(pkg, signed, buf)
    
    #print('package length ', len(pkg))
    #print('buf length ', len(buf))
    #with open('test_signature.p7s', 'wb') as testsign:
    #    testsign.write(pkg.read())
    #    testsign.write(buf.read())
    
    # Save seed file for PRNG
    Rand.save_file('/tmp/randpool.dat')
    
    # Write author signed package back into first buffer
    buf.write(pkg.read(232).replace(b'\n', b'\r\n'))
    #buf.write(pkg.read().replace(b's.p7s', b'author.p7s'))  # Two step process to fix name and EOL CRLF
    with open('data.txt', 'rb') as dt_file:
        for line in dt_file:
            buf.write(line)
    
    signature = BIO.MemoryBuffer()
    signature.write(pkg.read(191).replace(b'smime.p7s', b'author.p7s'))
    signature.write(au_signd)
    # skip over signature w/o OCSP response
    pkg.read(len(pkg) - 43) # Just get the last line to close package boundary
    signature.write(pkg.read())
    buf.write(signature.read().replace(b'\n', b'\r\n'))
    
    ##############################################
    # Now have Author signed APP back into buffer
    # Next, attach Distributor signing
    ##############################################
    
    
    # load distributor certificate
    s.load_key('distrib_key.pem', 'distrib_cert.pem')
    
    sd = cms.SignedData()
    #sd = cms.SignedAndEnvelopedData()
    
    # Populating some of its field
    sd['version']='v3'
    #sd['encap_content_info']=util.OrderedDict([ ('content_type', 'data'), ('content', buf.read()) ])
    sd['encap_content_info']=util.OrderedDict([ ('content_type', 'data'), ('content', b'dummy') ])
    sd['digest_algorithms']=[ util.OrderedDict([ ('algorithm', 'sha256'), ('parameters', None) ]) ]
    
    # Getting the raw value (DER) of distributor certificate and storing it in x509
    #cert = x509.Certificate.load(certObj[Attribute.VALUE])
    cert = x509.Certificate.load(dtca12[1].public_bytes(Encoding.DER))
    
    # Adding this certificate to SignedData object
    sd['certificates'] = [cert]
    
    # put OCSP response into CMS structure as OtherRevocationInfoFormat (OID = 1.3.6.1.5.5.7.16.2)
    # Adding Certificate Revocation List (CRL) - METHOD 1
    crlreply = ocsp.OCSPResponse()
    crlreply['response_status']=dt_ocsp_status.response_status.value
    crlreply['response_bytes']=ocsp.ResponseBytes.load(dt_resp_data)
    #sd['crls'] = [crlreply]
    
    # Adding Certificate Revocation List (CRL) - METHOD 2
    crlist = cms.OtherRevocationInfoFormat()
    crlist['other_rev_info_format'] = 'ocsp_response'
    crlist['other_rev_info'] = crlreply
    sd['crls'] = [crlist]
    
    # Adding Certificate Revocation List (CRL) - METHOD 3
    #ocspreply = cms.RevocationInfoChoices.load(dt_resp_data, strict=False, tag=16)
    #sd['crls'] = [ocspreply]
    
    # Setting signer info section
    signer_info = cms.SignerInfo()
    #signer_info['version']=cms_version
    signer_info['version']='v3'
    signer_info['digest_algorithm']=util.OrderedDict([('algorithm', 'sha256'), ('parameters', None) ])
    signer_info['signature_algorithm']=util.OrderedDict([('algorithm', 'sha256_rsa'), ('parameters', None) ])
    
    # Creating a signature
    # write the buffer to a file to use in command line
    with open('data.txt', 'wb') as dt_file:
         dt_file.write(buf.read())
    # refill the buffer
    with open('data.txt', 'rb') as dt_file:
        for line in dt_file:
            buf.write(line)
    
    #ossl_cmd = 'cms -sign -binary -in data.txt -md sha256 -signer distrib_cert.pem -inkey distrib_key.pem -out test_data.cms -outform PEM'
    ossl_cmd = 'cms -sign -binary -in data.txt -md sha256 -signer distrib_cert.pem -inkey distrib_key.pem -outform PEM'
    sign_cmd = openssl_location + " " + ossl_cmd
    #signing = subprocess.check_output(sign_cmd, shell=True)
    signer_info['signature'] = subprocess.check_output(sign_cmd, shell=True)
    
    # Finding subject_key_identifier from certificate (asn1crypto.x509 object)
    key_id = cert.key_identifier_value.native
    signer_info['sid'] = cms.SignerIdentifier({ 'subject_key_identifier': key_id })
    #print(signer_info)
    
    # Adding SignerInfo object to SignedData object
    sd['signer_infos'] = [ signer_info ]
    
    # Writing everything into ASN.1 object
    asn1obj = cms.ContentInfo()
    asn1obj['content_type'] = 'signed_data'
    asn1obj['content'] = sd
    #print(sd)
    
    # Place the signing at the end of the buffer (DER format)
    #with open('signed_data.der','wb+') as fout:
    #    fout.write(asn1obj.dump())
    #    fout.write(signer_info.dump())
    #buf.write(asn1obj.dump())
    #buf.write(base64.b64encode(asn1obj.dump()))
    #buf.write(base64.encodebytes(asn1obj.dump()))
    
    # Hold on to this signature with OCSP response
    dt_signd = base64.encodebytes(asn1obj.dump())
    
    # sign whole message with Distributor's certificate
    signed = s.sign(buf, SMIME.PKCS7_DETACHED, 'sha256')
    
    # write signature into now empty buffer
    s.write(pkg, signed, buf)
    
    #print('package length ', len(pkg))
    #print('buf length ', len(buf))
    #with open('test_signature.p7s', 'wb') as testsign:
    #    testsign.write(pkg.read())
    #    testsign.write(buf.read())
    
    # Write output file without lineending changes
    with open(d_file, 'wb') as out:
        out.write(pkg.read(232).replace(b'\n', b'\r\n'))
        with open('data.txt', 'rb') as dt_file:
            for line in dt_file:
                out.write(line)
        signature.write(pkg.read(191).replace(b'smime.p7s', b'distrib.p7s'))
        signature.write(dt_signd)
        # skip over signature w/o OCSP response
        pkg.read(len(pkg) - 43) # Just get the last line to close package boundary
        signature.write(pkg.read())        
        out.write(signature.read().replace(b'\n', b'\r\n'))


