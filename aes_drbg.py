from Crypto.Cipher import AES

class NIST_KAT_DRBG:
    """AES-256 CTR to extract "fake" DRBG outputs that are compatible with
        the randombutes() call in the NIST KAT testing suite."""

    def __init__(self, seed):
        self.seed_length = 48
        assert len(seed) == self.seed_length
        self.key = b'\x00'*32
        self.ctr = b'\x00'*16
        update = self.get_bytes(self.seed_length)
        update = bytes(a^b for a,b in zip(update,seed))
        self.key = update[:32]
        self.ctr = update[32:]

    def __increment_ctr(self):
        x = int.from_bytes(self.ctr, 'big') + 1
        self.ctr = x.to_bytes(16, byteorder='big')

    def get_bytes(self, num_bytes):
        tmp = b''
        cipher = AES.new(self.key, AES.MODE_ECB)
        while len(tmp) < num_bytes:
            self.__increment_ctr()
            tmp  += cipher.encrypt(self.ctr)
        return tmp[:num_bytes]

    def random_bytes(self, num_bytes):
        output_bytes = self.get_bytes(num_bytes)
        update = self.get_bytes(48)
        self.key = update[:32]
        self.ctr = update[32:]
        return output_bytes

class SeedExpander:
    def __init__(self, seed):
        """Initialize extractor with 'seed'."""
        key         =   seed + b'\x00' * (32 - len(seed))
        iv          =   b'\x00' * 12
        self.aes    =   AES.new(key, AES.MODE_CTR, nonce=iv, initial_value=0)
        self.x      =   0   #   partial value
        self.b      =   0   #   number of bits in x

    def bytes(self, sz):
        """Extract 'sz' bytes from the expander."""
        return self.aes.encrypt(b'\x00' * sz)

    def sample_max(self, n):
        """Extract value 0 <= x < n from the expander."""
        nb = int(n - 1).bit_length()
        while True:
            while self.b < nb:
                c = self.bytes(1)
                self.x  =   (self.x << 8) + c[0]
                self.b  +=  8
            r = self.x & ((1 << nb) - 1)
            self.x >>= nb
            self.b -= nb
            if r < n:
                return r

