#   forgery.py
#   2023-07-18  Markku-Juhani O. Saarinen < mjos@pqshield.com>. See LICENSE

from alteq import *
from aes_drbg import NIST_KAT_DRBG

#   This is the forgery call back function. just needs the message

def forge_lp1(alteq, msg, nz):

    #   assumes LP1 parameters here
    assert alteq.r - alteq.k == 2

    zz = bytes([0] * len(nz))
    for c1 in range(1,alteq.r):
        for c0 in range(0, c1):
            ch = alteq.hash(msg)
            for i in range(alteq.r):
                if i == c0 or i == c1:
                    ch += nz
                else:
                    ch += zz
            cha = alteq.hash(ch)
            (chg_c, chg_nc, chg_val) = alteq.expand_challenge(cha[0:alteq.seed_sz])
            if chg_c == [c0, c1]:
                return cha + bytes([0] * (alteq.sig_sz - 2*alteq.seed_sz)) + msg
    #   sometimes its not found
    return None

if (__name__ == "__main__"):

    iut = alteq_lp1

    #   generate the count=0 key pair
    drbg    = NIST_KAT_DRBG(bytes([i for i in range(48)]))
    seed    = drbg.random_bytes(48)
    iut.set_random(NIST_KAT_DRBG(seed).random_bytes)
    (pk, sk) = iut.keygen()

    print("hash_pk =", iut.hash(pk).hex().upper())
    print("hash_sk =", iut.hash(sk).hex().upper())
    del sk  # we don't need the secret key

    #   test our particular forgery
    msg = b'Forgery'
    fsm = (bytes.fromhex(
        'E4E7C61518AD2CE12B20D96734B665C0E7F61286186D21B1FD4BF5BD7019BAA3') +
        (b'\x00' * 9496) + b'Forgery')
    m2 = iut.open(fsm, pk)
    if m2 == None or m2 != msg:
        print("(forgery error)")
    else:
        print("forgery passes.")

    #   create an another forgery using the callback
    for i in range(10):
        msg = b'test' + bytes([48+i])
        sm = iut.open(msg, pk, forge=forge_lp1)
        if sm == None:
            print(i, "(not found)")
        else:
            m2 = iut.open(sm, pk)
            print(i, m2)

