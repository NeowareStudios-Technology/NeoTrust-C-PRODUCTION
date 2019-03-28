# NeoPak
Notes:

-signature in signature block file is in DER format

Process overview:

1)create manifest file that includes manifest file header and user's public key

2)create signature file that includes signature file header

3)generate digests from each file in target directory and save in manifest file

4)generate digests from each entry in manifest file and save in signature file

5)generate digest from entire manifest file and send Ethereum transaction that includes this digest and user's public key

6)append Ethereum transaction hash to manifest file

7)create digest from entire manifest file (again) and append this digest to signature file

8)generate digest from entire signature file, sign this digest with user's private key, and save signature in signature block file
