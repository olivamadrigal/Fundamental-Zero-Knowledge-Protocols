/*
zero-knowlege proofs

very nice and simple examples's taken from Massimo Bertaccini's 2022 book Cryptography Algorithms, I got this March.

nice to cover before or after learning where things come from, such as Graph Isomorphisms.

Then I would suggest homomorphic Encryption, and more involved ZPK constructions that entail elliptic curve pairs,
rank 1 constraint systems, and quadratic arithmetic programs.

Either way should be fine :)

NOTE these examples use the numerical examples provided in the book;
You may try out with different numbers by generating cryptographically secure random numbers using the BN API.
*/
#ifndef zkp_h
#define zkp_h

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <openssl/bn.h> //BN multiprecision strucuts
#include <openssl/rsa.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

/* NON-INTERACTIVE ZERO-KNOWDLEGE PROOF PROTOCOL based on RSA
scheme:
Prover (statement) ----> Proof of Knowledge ---> Verifier (verification)
*/
//EXAMPLE: Zero Knowledge Protocol with RSA with OpenSSL BIGNUMBER LIBRARY
void RSA_NIZK(void);


/* EXAMPPLE: Schnorr interactive ZKP can be used as an authentication scheme
Prover                                   Verifier
function V ----------------------------------->
<---------------------------------------random r
function w that embeds a --------------------->
                                    verifies g^w * B^r congruent to V mod p
*/
void Schnorr_IZKP(void);

/*
EXAMPLE: zk-SNARK based on discrete log problem :)
general example

G: key generator
P: proof
V: verifier algorithm
*/
void DH_zkSNARK(void);

#endif /* zkp_h */
