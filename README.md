# alteq-py

2023-07-18  Markku-Juhani O. Saarinen  mjos@pqshield.com


An [ALTEQ](https://pqcalteq.github.io/) implementation in Python, and a demonstration of a forgery attack.

The main file `alteq.py` can be used to generate the test vectors. The alteq site uses a more compact hashed test vector type; the code implements both this and the muuuch longer NIST KAT vectors.

The forgery against ShortSig-1 (LP1) parameter set is demonstrated by `forgery.py`. Test vectors, of course, don't guarantee that the signature verification function is perfectly implemented; I've checked the verification function against the reference C implementation.

##  OFFICIAL COMMENT: ALTEQ

__(this was posted on [pqc-forum](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/-LCPCJCyLlc/m/_ghV61NQBQAJ) on 2023-07-18 -- just a minor typo correction here.)__

Hi All,

I'll describe a simple signature forgery attack against ALTEQ.

An ALTEQ signature consists of three parts: (cha, seed_i, D_i). ALTEQ is built on the Fiat-Shamir transform, and the verify function checks cha==cha' where cha' is reconstructed using the public key and the message. We observe that the challenge space can be reduced to binomial(r,K) size simply by setting the "seed_i" and "D_i" parts of the signature to zeros. The attack consists of finding a matching expandChallenge() output in this reduced space.

We demonstrate the attack with a full forgery against Level I ShortSig-ALTEQ. The attack is especially easy in this case as we have r=16 and K=14.

The signed message "sm", expressed in Python as follows:

```
sm = (bytes.fromhex(
  'E4E7C61518AD2CE12B20D96734B665C0E7F61286186D21B1FD4BF5BD7019BAA3') +
  (b'\x00' * 9496) + b'Forgery')
```

Passes as valid with the first public key of the ShortSig-ALTEQ level I test vectors (in file `[..]/ref_mode_lp/1/PQCsignKAT_16.rsp`, starting `pk = 9F4602C4C84A05..`) I have checked this against the reference C implementation.

The forged signature consists of a 32-byte [corrected] challenge hash cha=E4E7C6.. with the rest of the signature (9496 bytes) set to zeros. This is a valid signature for 7-byte ASCII text 'Forgery' or  466F7267657279.

During verification of this signature, the input to the challenge hash cha' = H(H(M) |  psi'0 | psi'1 '| .. ) on line 11 in Vf function of Fig 2 of the spec) becomes:
```
idx    [len]  hex
-------------------------------------------------------------------------------
H(M):  [32]   67a14a46b32990b13d97fa4961c9baed4ba64d09b24c70e199f981d41824e70a
psi0:  [1144] 83044487cf6021aaa5ae526928fd54d4468e27a3810abd02d4bb08d86257ec44..
psi1:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi2:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi3:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi4:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi5:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi6:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi7:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi8:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi9:  [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi10: [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi11: [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi12: [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi13: [1144] 0000000000000000000000000000000000000000000000000000000000000000..
psi14: [1144] 83044487cf6021aaa5ae526928fd54d4468e27a3810abd02d4bb08d86257ec44..
psi15: [1144] 0000000000000000000000000000000000000000000000000000000000000000...
```

This is a collision as the two (r-K) non-zero vectors are expanded at the same locations by expandChallenge. We only had to perform binomial(16,14)=120 trials to find a match. Note that the non-zero vector 1144-byte vector 8304.. depends only on the public key.

The attack complexity is log2(binomial(r,K)) bits. One can observe the r and K parameters from Tables 2 and 3 in the specification -- the attack breaks all parameter sets much faster than indicated by the security category (at most 2^113 effort, even at Level 5.) The challenge space was apparently intended be  binomia(r,K)*C^K  which closely matches 2^lambda for all parameter sets.

An obvious countermeasure would be to filter the signature space against such pathological cases, but this was not done in the specification or the reference implementation.


Cheers,
-markku

Markku-Juhani O. Saarinen
