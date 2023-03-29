# ELAT - ECDSA Lattice Attack Toolkit

Provides an attack class to easily perform lattice-based attacks against ECDSA.

The lattice attack against ECDSA is an implementation of the paper ["Recovering cryptographic keys from aprtial information, by example" from De Micheli and Heninger](https://eprint.iacr.org/2020/1506.pdf). ELAT currently supports ECDSA key recovery from known most-significant and known least-significant bits of secret ECDSA signature nonces.

Future work:
* Implement ECDSA key recovery from (many chuncks of) known middle bits of the nonces.
* Replace sagemath dependency with fplll
