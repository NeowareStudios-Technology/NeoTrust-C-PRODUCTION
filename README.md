# NeoTrust

## Build insructions:

-build works on macOS Mojave Version 10.14.3

-Neopak: run ```make``` in the NeoTrust directory

-unit tests: run ```make test```in NeoTrust directory

-unit test results will be in "unittestresults.out"

## Process overview:

1)create manifest file that includes manifest file header and user's public key

2)create signature file that includes signature file header

3)generate digests from each file in target directory and save in manifest file

4)generate digests from each entry in manifest file and save in signature file

5)generate digest from entire manifest file and send Ethereum transaction that includes this digest

7)insert manifest file digest into signature file

6)insert Ethereum transaction hash to signature file

8)generate digest from entire signature file, sign this digest with user's private key, and save signature in signature block file

## General Notes:

-signature in signature block file is in DER format

-public key in manifest file is in compressed format (33 bytes)

## DukTape Notes:
-Built on macOS Mojave Version 10.14.3 

-DukTape has to be build with python 2  (including pyYaml) using this command: ```python tools/configurepy --output-directory duktap-src```
