# micro-ecc

[micro-ecc](https://github.com/kmackay/micro-ecc) at commit
`76fda53af41aed0a5b372227be65f69fcb502400`, BSD-2-Clause (`LICENSE.txt`):
ECDSA over P-256 (secp256r1) for `apkpack keygen`, `sign` and `verify`.
Copied unchanged; only `uECC.c`, its headers and the `.inc` files it
includes. Built with only secp256r1 (the Makefile's `-DuECC_SUPPORTS_*`).
