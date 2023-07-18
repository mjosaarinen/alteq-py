#   alteq.py
#   2023-07-16  Markku-Juhani O. Saarinen < mjos@pqshield.com>. See LICENSE

import os,sys
from aes_drbg import NIST_KAT_DRBG,SeedExpander
from Crypto.Hash import SHA3_256,SHA3_384,SHA3_512

class Alteq:

    #   initialize
    def __init__(self, la=128, n=13, q=2**32-5, r=84, k=22, c=7,
                        param_id='fe1', rbg=os.urandom):
        self.rbg        =   rbg
        self.algname    =   "ALTEQ"
        self.param_id   =   param_id
        self.n          =   n
        self.q          =   q
        self.r          =   r
        self.k          =   k
        self.c          =   c
        self.seed_sz    =   la // 8
        self.atfc_len   =   (n * (n - 1) * (n - 2) // 6)
        self.alt_sz     =   (self.atfc_len * int(q).bit_length() + 7) // 8
        self.pk_sz      =   c * self.alt_sz + self.seed_sz
        self.sk_sz      =   la // 8
        self.sig_sz     =   ((((r - k + 2) * la)
                                + (k * n**2 * int(q).bit_length()) + 7) // 8)
        if  la == 128:
            self.sha3   =   SHA3_256
        elif la == 192:
            self.sha3   =   SHA3_384
        elif la == 256:
            self.sha3   =   SHA3_512

    #   --- public functions
    def set_random(self, rbg):
        """Set the key material RBG."""
        self.rbg   =   rbg

    def keygen(self):
        """Generate a keypair (pk,sk)."""
        sk = self.rbg(self.sk_sz)
        seeds = self.expand_seeds(sk, self.c + 1)
        atfc = self.expand_atfc(seeds[self.c])
        pk = b''
        for i in range(self.c):
            cols = self.expand_columns(seeds[i])
            atf = self.decompress_atf(atfc)
            self.inverting_on_atf(atf, cols)
            pk += self.compress_array(self.compress_atf(atf))
        pk += seeds[self.c]
        return (pk, sk)

    def sign(self, msg, sk):
        """Sign message 'msg' with the secret key 'sk'."""
        #   expand secret key
        seeds_sk = self.expand_seeds(sk, self.c + 1)
        atfc = self.expand_atfc(seeds_sk[self.c])

        #   create r random N column matrices
        rnd = self.rbg(self.seed_sz)
        seeds_rnd = self.expand_seeds(rnd, self.r)
        cols_rnd = []
        for i in range(self.r):
            cols_rnd += [ self.expand_columns(seeds_rnd[i]) ]

        #   create challenge from hash
        ch = self.hash(msg)

        #   "acting independently"
        for i in range(self.r):
            atf = self.decompress_atf(atfc)
            for j in range(self.n):
                self.acting_on_atf_col(atf, cols_rnd[i][j], j)
            ch += self.compress_array(self.compress_atf(atf))

        sm  =   self.hash(ch)
        (chg_c, chg_nc, chg_val) =  self.expand_challenge(sm[0:self.seed_sz])

        #   add seeds to signature
        for i in range(self.r - self.k):
            sm += seeds_rnd[chg_c[i]]

        #   product
        cols_sk = [None] * self.c
        for i in range(self.k):
            cs = chg_val[i]
            cr = chg_nc[i]
            if cols_sk[cs] == None:
                cols_sk[cs] = self.expand_columns(seeds_sk[cs])
            mat = self.mat_col_prod(cols_rnd[cr], cols_sk[cs])
            for j in range(self.n):
                sm += self.compress_array(mat[j])

        #   add message
        sm += msg
        return  sm

    def open(self, sm, pk, forge=None):
        """Open signed message. Return None on failure, msg on success."""
        if forge == None:
            #   regular verify fucntion
            if len(sm) < self.sig_sz or len(pk) != self.pk_sz:
                return None
            sig = sm[:self.sig_sz]
            msg = sm[self.sig_sz:]
        else:
            #   set stuff up for forging
            sig = bytes([0] * self.sig_sz)
            msg = sm

        #   decode public key
        atfs = []
        pk_idx = 0
        for i in range(self.c):
            atfs += [ self.decompress_array( pk[pk_idx : pk_idx + self.alt_sz]) ]
            pk_idx += self.alt_sz

        #   expand ATF_C
        atfc = self.expand_atfc(pk[pk_idx : pk_idx + self.seed_sz])

        #   expand challenge
        cha = sig[0:2*self.seed_sz]
        sig_idx = 2*self.seed_sz
        (chg_c, chg_nc, chg_val) = self.expand_challenge(cha[0:self.seed_sz])

        #   expand r-k column matrices corresponding to challenge =c
        cols_sig = []
        for i in range(self.r - self.k):
            seed_sig = sig[sig_idx:sig_idx + self.seed_sz]
            sig_idx += self.seed_sz
            cols_sig += [ self.expand_columns(seed_sig) ]

        #   recreate the challenge
        ch_atf = [None] * self.r
        for i in range(self.r - self.k):
            atf = self.decompress_atf(atfc)
            for j in range(self.n):
                self.acting_on_atf_col(atf, cols_sig[i][j], j)
            ch_atf[chg_c[i]] = self.compress_array(self.compress_atf(atf))

        row_sz = 4 * self.n
        for i in range(self.k):
            mat = []
            for j in range(self.n):
                mat += [ self.decompress_array(
                                sig[sig_idx:sig_idx + row_sz] ) ]
                sig_idx += row_sz
            atf = self.tensor_mat( atfs[chg_val[i]], mat )
            ch_atf[chg_nc[i]] = self.compress_array(atf)

        #   create challenge from hash
        ch = self.hash(msg)
        for i in range(self.r):
            ch += ch_atf[i]
        chap = self.hash(ch)

        #   call the forgery function
        if forge != None:
            return forge(self, msg, ch_atf[chg_c[0]])

        #   check equivalence
        if cha == chap:
            return msg

        return None

    #   --- internal functions

    def hash(self, data):
        return self.sha3.new(data).digest()

    def mat_col_mul(self, mat, col, j, s):
        for i in range(self.n):
            a = col[i]
            if i != j:
                for k in range(s, self.n):
                    mat[i][k] = (mat[i][k] + mat[j][k] * a) % self.q
        a = col[j]
        for k in range(s, self.n):
            mat[j][k] = (mat[j][k] * a) % self.q

    def mat_col_prod(self, ca, cb):
        #   transpose
        mat = [ [ ca[i][j] for i in range(self.n) ]
                            for j in range(self.n) ]
        for j in range(self.n-1,-1,-1):
            self.mat_col_mul(mat, ca[j], j, j + 1)
        for j in range(self.n-1,-1,-1):
            self.mat_col_mul(mat, cb[j], j, 0)
        return mat

    def compress_array(self, v):
        y = b''
        for x in v:
            x %= self.q
            y += bytes([x & 0xFF, (x >> 8) & 0xFF,
                        (x >> 16) & 0xFF, (x >> 24) & 0xFF])
        return y

    def decompress_array(self, y):
        v = []
        for i in range(0, len(y), 4):
            v += [  y[i] +              (y[i + 1] << 8) +
                    (y[i + 2] << 16) +  (y[i + 3] << 24) ]
        return v

    def expand(self, se, x_sz):
        return se.encrypt(b'\x00' * x_sz)

    def expand_seeds(self, seed, n_seeds):
        se = SeedExpander(seed)
        return [ se.bytes(self.seed_sz) for _ in range(n_seeds) ]

    def expand_atfc(self, seed):
        se  = SeedExpander(seed)
        r   = []
        while True:
            s16 = self.decompress_array(se.bytes(4*16))
            for x in s16:
                if x < self.q:
                    r += [x]
                    if len(r) >= self.atfc_len:
                        return r

    def expand_columns(self, seed):
        """n * n  matrix from seed without zeros on the diagona."""
        se  = SeedExpander(seed)
        r   = [ [0] * self.n for _ in range(self.n) ]
        i   = 0
        j   = 0
        while True:
            s16 = self.decompress_array(se.bytes(4*16))
            for x in s16:
                if (x < self.q) and (i != j or x > 0):
                    r[i][j] = x
                    j += 1
                    if j == self.n:
                        j = 0
                        i += 1
                        if i == self.n:
                            return r

    def expand_challenge(self, seed):
        se = SeedExpander(seed)

        if self.r - self.k < self.k:
            #   set R-K coefficients to C
            chg = [0] * self.r
            for k in range(self.r - self.k):
                r = se.sample_max(self.r - k)
                i = 0
                while i <= r:
                    if chg[i] == self.c:
                        r += 1
                    i += 1
                chg[r] = self.c

            #   set other coefficients randomly
            for i in range(self.r):
                if chg[i] == 0:
                    chg[i] = se.sample_max(self.c)

        else:
            #   pick randomly K coefficients of the challenge to be < C
            chg = [ self.c ] * self.r
            for k in range(self.k):
                r = se.sample_max(self.r - k)
                i = 0
                while i <= r:
                    if chg[i] < self.c:
                        r += 1
                    i += 1
                chg[r] = se.sample_max(self.c)

        #   collect
        chg_c = []
        chg_nc = []
        chg_val = []
        for i in range(self.r):
            if chg[i] < self.c:
                chg_nc += [ i ]
                chg_val += [ chg[i] ]
            else:
                chg_c += [ i ]

        return (chg_c, chg_nc, chg_val)

    def decompress_atf(self, atfc):
        """Decompress a compressed ATF."""
        idx = 0
        atf = [ [ [0] * self.n  for _ in range(self.n) ]
                                    for _ in range(self.n) ]
        for i in range(self.n - 2):
            for j in range(i + 1, self.n - 1):
                for k in range(j + 1, self.n):
                    atf[i][j][k] = atfc[idx]
                    idx += 1
        return atf

    def compress_atf(self, atf):
        """Compress an ATF."""
        atfc = []
        for i in range(self.n - 2):
            for j in range(i + 1, self.n - 1):
                for k in range(j + 1, self.n):
                    atfc += [ atf[i][j][k] ]
        return atfc

    def q_inv(self, a):
        """Return a^-1 (mod q) -- if exists."""
        (r0, r1) = (a, self.q)
        (s0, s1) = (1, 0)
        while r1 != 0:
            q = r0 // r1
            (r0, r1) = (r1, r0 - q * r1)
            (s0, s1) = (s1, s0 - q * s1)
        return s0 % self.q

    def inverting_on_atf(self, atf, cols):
        """Perform inverting on atf (in place.)"""
        diag = [ self.q_inv(cols[i][i]) for i in range(self.n) ]
        col = [0] * self.n
        for j in range(self.n - 1, -1, -1):
            for i in range(self.n):
                if i != j:
                    col[i] = (self.q - diag[j]) * cols[j][i]
            col[j] = diag[j]
            self.acting_on_atf_col(atf, col, j)
        return atf

    def acting_on_atf_col(self, atf, col, j):
        #   ORDER k,l,i

        #   k < l < j
        for k in range(j-1):
            for l in range(k+1, j):
                atf[k][l][j]    =   (col[j] * atf[k][l][j]) % self.q

        #   k < j < l
        for k in range(j):
            for l in range(j+1, self.n):
                atf[k][j][l]    =   (col[j] * atf[k][j][l]) % self.q

        #   j < k < l
        for k in range(j+1, self.n-1):
            for l in range(k+1, self.n):
                atf[j][k][l]    =   (col[j] * atf[j][k][l] ) % self.q

        #   k < l < i < j
        for k in range(j-2):
            for l in range(k+1, j-1):
                for i in range(l+1, j):
                    atf[k][l][j]    +=  (col[i] * atf[k][l][i]) % self.q

        #   k < i < l < j
        for k in range(j-2):
            for l in range(k+2, j):
                for i in range(k+1, l):
                    atf[k][l][j]    -=  (col[i] * atf[k][i][l]) % self.q

        #   k < i < j < l
        for k in range(j-1):
            for l in range(j+1, self.n):
                for i in range(k+1, j):
                    atf[k][j][l]    +=  (col[i] * atf[k][i][l]) % self.q

        #   i < k < l < j
        for k in range(1, j-1):
            for l in range(k+1, j):
                for i in range(k):
                    atf[k][l][j]    +=  (col[i] * atf[i][k][l]) % self.q

        #   i < k < j < l
        for k in range(1, j):
            for l in range(j+1, self.n):
                for i in range(k):
                    atf[k][j][l]    -=  (col[i] * atf[i][k][l]) % self.q

        #   i < j < k < l
        for k in range(j+1, self.n-1):
            for l in range(k+1, self.n):
                for i in range(j):
                    atf[j][k][l]    +=  (col[i] * atf[i][k][l]) % self.q

        #   k < l < j < i
        for k in range(j-1):
            for l in range(k+1, j):
                for i in range(j+1, self.n):
                    atf[k][l][j]    +=  (col[i] * atf[k][l][i]) % self.q

        #   k < j < l < i
        for k in range(j):
            for l in range(j+1, self.n-1):
                for i in range(l+1, self.n):
                    atf[k][j][l]    -=  (col[i] * atf[k][l][i]) % self.q

        #   k < j < i < l
        for k in range(j):
            for l in range(j+2, self.n):
                for i in range(j+1, l):
                    atf[k][j][l]    +=  (col[i] * atf[k][i][l]) % self.q

        #   j < k < l < i
        for k in range(j+1, self.n-2):
            for l in range(k+1, self.n-1):
                for i in range(l+1, self.n):
                    atf[j][k][l]    +=  (col[i] * atf[k][l][i]) % self.q

        #   j < k < i < l
        for k in range(j+1, self.n-2):
            for l in range(k+2, self.n):
                for i in range(k+1, l):
                    atf[j][k][l]    -=  (col[i] * atf[k][i][l]) % self.q

        #   j < i < k < l
        for k in range(j+2, self.n-1):
            for l in range(k+1, self.n):
                for i in range(j+1, k):
                    atf[j][k][l]    +=  (col[i] * atf[i][k][l]) % self.q

        #   RED
        for k in range(j-1):
            for l in range(k+1, j):
                atf[k][l][j]    =   atf[k][l][j] % self.q

        for k in range(j):
            for l in range(j+1, self.n):
                atf[k][j][l]    =   atf[k][j][l] % self.q

        for k in range(j+1, self.n-1):
            for l in range(k+1, self.n):
                atf[j][k][l]    =   atf[j][k][l] % self.q

    def tensor_mat(self, atf, mat):

        ta = [ [ [0] * self.n for _ in range(self.n) ]
                                    for _ in range(self.n) ]
        tb = [ [ [0] * self.n for _ in range(self.n) ]
                                    for _ in range(self.n) ]

        idx = 0
        for i in range(self.n - 2):
            for j in range(i + 1, self.n - 1):
                for k in range(j + 1, self.n):
                    x = atf[idx]
                    idx += 1
                    ta[i][j][k] = x
                    ta[j][i][k] = -x
                    ta[k][j][i] = -x
                    ta[i][k][j] = -x
                    ta[j][k][i] = x
                    ta[k][i][j] = x

        for i in range(self.n):
            for j in range(self.n):
                for k in range(self.n):
                    x = 0;
                    for l in range(self.n):
                        x = (x + mat[l][j] * ta[i][l][k]) % self.q
                    tb[i][j][k] = x

        for i in range(self.n):
            for j in range(self.n):
                for k in range(j + 1, self.n):
                    x = 0;
                    for l in range(self.n):
                        x = (x + mat[l][k] * tb[i][j][l]) % self.q
                    ta[i][j][k] = x

        atf_out = []
        for i in range(self.n - 2):
            for j in range(i + 1, self.n - 1):
                for k in range(j + 1, self.n):
                    x = 0
                    for l in range(self.n):
                        x = (x + mat[l][i] * ta[l][j][k]) % self.q
                    atf_out += [ x ]

        return atf_out

#   balanced parameter sets
alteq_fe1 = Alteq(la=128, n=13, q=2**32-5, r=84,  k=22, c=7, param_id='fe1')
alteq_fe3 = Alteq(la=192, n=20, q=2**32-5, r=201, k=28, c=7, param_id='fe3')
alteq_fe5 = Alteq(la=256, n=25, q=2**32-5, r=119, k=48, c=8, param_id='fe5')

#   short signature
alteq_lp1 = Alteq(la=128, n=13, q=2**32-5, r=16, k=14, c=458, param_id='lp1')
alteq_lp3 = Alteq(la=192, n=20, q=2**32-5, r=39, k=20, c=229, param_id='lp3')
alteq_lp5 = Alteq(la=256, n=25, q=2**32-5, r=67, k=25, c=227, param_id='lp5')

alteq_all = [   alteq_fe1, alteq_fe3, alteq_fe5,
                alteq_lp1, alteq_lp3, alteq_lp5 ]

#   test bench

def test_rsp(iut, katnum=100, hashkat=False):
    """Print NIST-styte KAT response files (or ALTEQ hashed KATs)."""
    drbg    = NIST_KAT_DRBG(bytes([i for i in range(48)]))
    print(f"# {iut.algname}\n")
    for count in range(katnum):
        print("count =", count)
        seed = drbg.random_bytes(48)
        iut.set_random(NIST_KAT_DRBG(seed).random_bytes)
        print("seed =", seed.hex().upper())
        mlen = 33 * (count + 1)
        print("mlen =", mlen)
        msg = drbg.random_bytes(mlen)
        print("msg =", msg.hex().upper())
        (pk, sk) = iut.keygen()
        if hashkat:
            print("hash_pk =", iut.hash(pk).hex().upper())
            print("hash_sk =", iut.hash(sk).hex().upper())
        else:
            print("pk =", pk.hex().upper())
            print("sk =", sk.hex().upper())
        sm = iut.sign(msg, sk)
        print("smlen =", len(sm))
        if hashkat:
            print("hash_sm =", iut.hash(sm).hex().upper())
        else:
            print("sm =", sm.hex().upper())
        print()
        m2 = iut.open(sm, pk)
        if m2 == None or m2 != msg:
            print("(verify error)")

if (__name__ == "__main__"):
    test_rsp(alteq_lp1, 100, True)

