import os
import sys
import ecdsa
import hashlib
import unittest

import elat

class TestParams:
    def __init__(self,
                 num_traces: int,
                 known_bits: int,
                 rebalance: bool,
                 msb: bool,
                 zerobits: bool,
                 curve_name: str,
                 hashfn):
        self.num_traces = num_traces
        self.known_bits = known_bits
        self.rebalance = rebalance
        self.msb = msb
        self.zerobits = zerobits
        self.curve_name = curve_name
        self.hashfn = hashfn
        return
    
    def __repr__(self) -> str:
        return self.__str__()
    
    def __str__(self) -> str:
        return f"TestCase(num_traces={self.num_traces}, known_bits={self.known_bits}, rebalance={self.rebalance}, msb={self.msb}, zerobits={self.zerobits}, curve={self.curve_name}, hash={self.hashfn.__name__})"
    pass
# END TestParams

class ECDSALatticeAttackTest:

    def __init__(self, testcase: TestParams):
        self.testcase = testcase
        self.num_traces = testcase.num_traces
        self.known_bits = testcase.known_bits
        self.rebalance = testcase.rebalance
        self.msb = testcase.msb
        self.zerobits = testcase.zerobits
        self.hashfn = testcase.hashfn
        self.curve = ecdsa.curves.curve_by_name(testcase.curve_name)
        self.ecparams = self._getECParams()
        return

    def run(self) -> bool:
        attack = elat.ECDSALatticeAttack(self.ecparams, self.known_bits, self.msb, self.zerobits, self.rebalance)
        privkey = ecdsa.SigningKey.generate(curve=self.curve)
        pubkey = privkey.get_verifying_key()
        for ii in range(self.num_traces):
            msg = os.urandom(16)
            trace = self._generate_trace(msg, privkey, self.hashfn, debug=ii == self.num_traces - 1)
            assert pubkey.verify(trace.r + trace.s, trace.m, hashfunc=self.hashfn)
            attack.add_trace(trace)
            pass
        sk0, sk1 = attack.compute_privkey_candidates()
        return ecdsa.SigningKey.from_secret_exponent(sk0, curve=self.curve) == privkey or ecdsa.SigningKey.from_secret_exponent(sk1, curve=self.curve) == privkey

    def _getECParams(self) -> elat.ECParams:
        bits = int(self.curve.baselen) * 8
        pp = int(self.curve.curve.p())
        aa = int(self.curve.curve.a())
        bb = int(self.curve.curve.b())
        Gx = int(self.curve.generator.x())
        Gy = int(self.curve.generator.y())
        nn = int(self.curve.order)
        return elat.ECParams(self.curve.name, bits, pp, aa, bb, Gx, Gy, nn)
    
    def _getNonce(self) -> int:
        k = bytearray(os.urandom(self.ecparams.bits // 8))
        while int.from_bytes(k, 'big') >= self.ecparams.n:
            k = bytearray(os.urandom(self.ecparams.bits // 8))
            pass
        if self.zerobits:
            for i in range(self.known_bits // 8):
                if self.msb:
                    k[i] = 0
                    pass
                else:
                    k[-i - 1] = 0
                    pass
                pass
            if self.known_bits % 8 != 0:
                if self.msb:
                    mask = ((1 << (8 - (self.known_bits % 8))) - 1)
                    k[self.known_bits//8] = k[self.known_bits//8] & mask
                    pass
                else:
                    mask = (0xFF << (self.known_bits % 8)) & 0xFF
                    k[-(self.known_bits//8) - 1] = k[-(self.known_bits//8) - 1] & mask
                    pass
                pass
            pass
        return int.from_bytes(k, 'big')
    
    def _generate_trace(self, data: bytes, sk: ecdsa.SigningKey, hashfn, debug: bool = False) -> elat.ECDSATrace:
        mask = ((1 << self.ecparams.bits) - 1)
        bits = self.ecparams.bits - self.known_bits
        if self.msb:
            mask = (mask << bits) & mask
            pass
        else:
            mask = (mask >> bits) & mask
            pass
        nonce = self._getNonce()
        sig = sk.sign(data, k=nonce, hashfunc=hashfn)
        hh: bytes = hashfn(data).digest()
        aa: bytes = self._int2bytes(nonce & mask)
        rr: bytes = sig[:self.curve.signature_length//2]
        ss: bytes = sig[self.curve.signature_length//2:]
        mm: bytes = data
        return elat.ECDSATrace(hh, aa, rr, ss, mm)
    
    def _int2bytes(self, val: int) -> bytes:
        return val.to_bytes(self.curve.baselen, 'big')
    
    def __repr__(self) -> str:
        return self.__str__()
    
    def __str__(self) -> str:
        s = f"TestCase:\n"
        s += f"\tEC Params ({self.curve.name}):\n"
        s += f"\t\tbits: {self.ecparams.bits}\n"
        s += f"\t\t   p: {self._int2bytes(self.ecparams.p).hex()}\n"
        s += f"\t\t   a: {self._int2bytes(self.ecparams.a % self.ecparams.p).hex()}\n"
        s += f"\t\t   b: {self._int2bytes(self.ecparams.b % self.ecparams.p).hex()}\n"
        s += f"\t\t  Gx: {self._int2bytes(self.ecparams.Gx).hex()}\n"
        s += f"\t\t  Gy: {self._int2bytes(self.ecparams.Gy).hex()}\n"
        s += f"\t\t   n: {self._int2bytes(self.ecparams.n).hex()}\n"
        s += f"\t{self.testcase}"
        return s
    pass
# END ECDSALatticeAttackTest

class TestCase_Collection(unittest.TestCase):
    NUM_TRACES = 10
    KNOWN_BITS = 128
    CURVE_NAME = 'NIST256p'
    HASH_FUNC  = hashlib.sha256

    def test_notRebalance_Msb_Zero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=False, msb=True,  zerobits=True,  curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return

    def test_notRebalance_Msb_notZero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=False, msb=True,  zerobits=False, curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return

    def test_notRebalance_Lsb_Zero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=False, msb=False, zerobits=True,  curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return

    def test_notRebalance_Lsb_notZero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=False, msb=False, zerobits=False, curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return

    def test_Rebalance_Msb_Zero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=True,  msb=True,  zerobits=True,  curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return

    def test_Rebalance_Msb_notZero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=True,  msb=True,  zerobits=False, curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return

    def test_Rebalance_Lsb_Zero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=True,  msb=False, zerobits=True,  curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return

    def test_Rebalance_Lsb_notZero(self):
        self.assertTrue(
            run_test(
                TestParams(self.NUM_TRACES, self.KNOWN_BITS, rebalance=True,  msb=False, zerobits=False, curve_name=self.CURVE_NAME, hashfn=self.HASH_FUNC)
                )
            )
        return
    pass
# END TestCase_Collection

class NIST192p_SHA1_TestCase(TestCase_Collection):
    NUM_TRACES = 10
    KNOWN_BITS = 96
    CURVE_NAME = 'NIST192p'
    HASH_FUNC  = hashlib.sha1
    pass
# END NIST192p_SHA1_TestCase

class NIST256p_SHA1_TestCase(TestCase_Collection):
    NUM_TRACES = 10
    KNOWN_BITS = 128
    CURVE_NAME = 'NIST256p'
    HASH_FUNC  = hashlib.sha1
    pass
# END NIST256p_SHA1_TestCase

class NIST256p_SHA256_TestCase(TestCase_Collection):
    NUM_TRACES = 10
    KNOWN_BITS = 128
    CURVE_NAME = 'NIST256p'
    HASH_FUNC  = hashlib.sha256
    pass
# END NIST256p_SHA256_TestCase

class NIST256p_SHA256_TestCase_2(TestCase_Collection):
    NUM_TRACES = 70
    KNOWN_BITS = 8
    CURVE_NAME = 'NIST256p'
    HASH_FUNC  = hashlib.sha256
    pass
# END NIST256p_SHA256_TestCase_2

class BRAINPOOLP256r1_SHA1_TestCase(TestCase_Collection):
    NUM_TRACES = 10
    KNOWN_BITS = 128
    CURVE_NAME = 'BRAINPOOLP256r1'
    HASH_FUNC  = hashlib.sha1
    pass
# END BRAINPOOLP256r1_SHA1_TestCase

class BRAINPOOLP256r1_SHA256_TestCase(TestCase_Collection):
    NUM_TRACES = 10
    KNOWN_BITS = 128
    CURVE_NAME = 'BRAINPOOLP256r1'
    HASH_FUNC  = hashlib.sha256
    pass
# END BRAINPOOLP256r1_SHA256_TestCase

class SECP256k1_SHA1_TestCase(TestCase_Collection):
    NUM_TRACES = 10
    KNOWN_BITS = 128
    CURVE_NAME = 'SECP256k1'
    HASH_FUNC  = hashlib.sha1
    pass
# END SECP256k1_SHA1_TestCase

class SECP256k1_SHA256_TestCase(TestCase_Collection):
    NUM_TRACES = 10
    KNOWN_BITS = 128
    CURVE_NAME = 'SECP256k1'
    HASH_FUNC  = hashlib.sha256
    pass
# END SECP256k1_SHA256_TestCase

def run_test(testcase: TestParams) -> bool:
    test = ECDSALatticeAttackTest(testcase)
    return test.run()

if __name__ == '__main__':
    unittest.main()
    pass
