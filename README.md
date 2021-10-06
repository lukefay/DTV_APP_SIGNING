# DTV_APP_SIGNING
Application signing compliant to ATSC A/360

This Python 3 script takes in a ZIP file, wraps it into a MIME package and then signs it according to ATSC A/360.

There are more than a few libraries involved.  Starting from scratch in a Unix environment, to build the Python 3 environment follow:
1. apt-get install gcc-core libssl-devel swig openssl clang libcrypt-devel zip gzip w32api jpeg libjpeg-devel libip libzip-devel openssl-devel
2. apt-get install python2 python2-devel python2-pip
3. python -m pip install invoke pyopenssl cryptography image wheel
4. python -m pip install M2Crypto
5. apt-get install python3 python3-devel python3-pip
6. export CRYPTOGRAPHY_DONT_BUILD_RUST='1'
7. python3 -m pip install crypto pyasn1 smime
8. python3 -m pip install M2Crypto
9. python3 -m pip install --upgrade cryptography

This also works on an Xserver like MobaXterm.

The script arguments are a zipped application file (or any file) to input, the output filename, the author certificates (and intermediate chain certs) in a .p12 file, the distributor certificates and a password to unlock those .p12 files.
