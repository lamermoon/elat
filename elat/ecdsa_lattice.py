from sage.all import lift, QQ, GF, Matrix, Rational, EllipticCurve
from sage.rings.finite_rings.integer_mod import IntegerMod_gmp as IntMod

class ECDSALatticeAttackError(ValueError):
    ''' A class to represent any errors when running the attack '''

    pass
# END ECDSALatticeAttackError

class ECParams:
    '''
    This class represents all parameters that idetify the elliptic curve
    that the ECDSA implementation under attack uses.

    Attributes
    ----------
    name : str
        the name of the curve as defined in the ecdsa package
    bits : int
        the number of bits that are used to represent the modulus of the curve
        this number is usually part of the curve's name
    p : int
        the modulus of the elliptic curve
    a : int
        the first parameter of the elliptic curve
    b : int
        the second parameter of the elliptic curve
    Gx: int
        the x-coordinate of the curve's generator point G
    Gy : int
        the y-coordinate of the curve's generator point G
    n : int
        the order of the generator point G
    '''

    def __init__(self, name: str, bits: int, p: int, a: int, b: int, Gx: int, Gy: int, n: int):
        '''
        Parameters
        ----------
        name : str
            the name of the curve as defined in the ecdsa package
        bits : int
            the number of bits that are used to represent the modulus of the curve
            this number is usually part of the curve's name
        p : int
            the modulus of the elliptic curve
        a : int
            the first parameter of the elliptic curve
        b : int
            the second parameter of the elliptic curve
        Gx: int
            the x-coordinate of the curve's generator point G
        Gy : int
            the y-coordinate of the curve's generator point G
        n : int
            the order of the generator point G
        '''
        self.name = name
        self.bits = bits
        self.p = p
        self.a = a
        self.b = b
        self.Gx = Gx
        self.Gy = Gy
        self.n = n
        return

    def __repr__(self):
        ''' Returns a representation of this object. '''
        return self.__str__()

    def __str__(self) -> str:
        ''' Returns a string representation of this object '''
        ans = f"ECParams(h={self.h.hex()}, a={self.a.hex()}, r={self.r.hex()}, s={self.s.hex()}, m={self.m.hex()})"
        return ans
    pass
# END ECParams

class ECDSATrace:
    '''
    This class represents a trace of ECDSA leakage.

    Attributes
    ----------
    h : bytes
        the hash value of the message that was signed
    a : bytes
        the leakage value that contains the known bits of the secret ECDSA nonce
    r : bytes
        the first part of the signature
    s : bytes
        the second part of the signature
    m : bytes
        the message that was signed
    '''
    def __init__(self, h: bytes, a: bytes, r: bytes, s: bytes, m: bytes):
        '''
        Parameters
        ----------
        h : bytes
            the hash value of the message that was signed
        a : bytes
            the leakage value that contains the known bits of the secret ECDSA nonce
        r : bytes
            the first part of the signature
        s : bytes
            the second part of the signature
        m : bytes
            the message that was signed
        '''
        self.h = h
        self.a = a
        self.r = r
        self.s = s
        self.m = m
        return

    def __repr__(self):
        ''' Returns a representation of this object. '''
        return self.__str__()

    def __str__(self) -> str:
        ''' Returns a string representation of this object. '''
        ans = f"ECDSATrace(h={self.h.hex()}, a={self.a.hex()}, r={self.r.hex()}, s={self.s.hex()}, m={self.m.hex()})"
        return ans
    pass
# END ECDSATrace

class ECDSALatticeAttack:
    '''
    This class is used to perform a lattice attack.

    Currently supported modes:
    * some most-significant bits of the secret ECDSA nonce are known
        * known bits are zero
        * known bits are not zero
    * some least-significant bits of the secret ECDSA nonce are known
        * known bits are zero
        * known bits are not zero
    
    Currently not supported:
    * some bits in the middle of the secret ECDSA nonce are known

    For all supported modes the rebalance trick is supported.
    If your attack attempt fails and you cannot collect more
    traces, the you should try the rebalancing trick.
    Rebalancing behaves as if you know an additional bit of the
    secret nonce.

    Attributes
    ----------
    traces : list[ECDSATrace]
        a list with side-channel traces that are to be used by the attack
    known_bits : int
        the number of secret nonce bits that are known per trace
    MSB : bool
        decides whether the most- or least-significant bits
        of the secret nonces are known (default True)
    zerobits : bool
        decides whether the known bits are all zero or not
        (default True)
    rebalance : bool
        optimizes the attack (default False)
    ec_name : str
        the name of the elliptic curve that is used
        by the ECDSA implementation under attack
    ec_bits : int
        the number of bits needed to represent
        the elliptic curve modulus
    pp : int
        the modulus of the elliptic curve
    Fp : FiniteField
        the sagemath class representing the finite field modulo pp
    EE : EllipticCurve
        the sagemath class representing the elliptic curve in use
    GG : EllipticCurvePoint
        the sagemath class representing the elliptic curve generator point in use
    nn : int
        the order of GG
    Fn : FiniteField
        the sagemath class representing the finite field modulo nn
    
    Methods
    -------
    add_trace(trace: ECDSATrace) -> None
        adds a trace to the traces list
    compute_privkey_candidates() -> tuple[int, int]
        performs a lattice attack to compute
        the private ECDSA key candidates
    '''

    def __init__(
            self,
            ecparams: ECParams,
            known_bits: int,
            MSB: bool = True,
            zerobits: bool = True,
            rebalance: bool = False
        ):
        '''
        Parameters
        ----------
        ecparams : ECParams
            the parameters of the elliptic curve used by the ECDSA
            implementation under attack
        known_bits : int
            the number of secret nonce bits that are known per trace
        MSB : bool
            decides whether the most- or least-significant bits
            of the secret nonces are known (default True)
        zerobits : bool
            decides whether the known bits are all zero or not
            (default True)
        rebalance : bool
            optimizes the attack (default False)
        '''
        self.known_bits = known_bits
        self.MSB = MSB
        self.zerobits = zerobits
        self.rebalance = rebalance
        self.traces = list()
        self._set_ec_params(ecparams)
        return
    
    def add_trace(self, trace: ECDSATrace) -> None:
        '''Adds a trace to the internal list of traces

        Parameters
        ----------
        trace : ECDSATrace
            the trace to be added
        '''
        self.traces.append(trace)
        return
    
    def compute_privkey_candidates(self) -> tuple[int, int]: 
        '''Computes the two possible private key candidates matching the given traces

        Performs a lattice attack against ECDSA following De Micheli and Heninger.
        Paper: https://eprint.iacr.org/2020/1506.pdf

        Two key candidates are returned in case the ECDSA algorithm normalizes signatures.
        This is, e.g., done by some blockchains like Bitcoin to prevent signature forgeries.
        If no normalization is performed, the first of the two candidates should be the right key.
        Otherwise, both candidates have to be tested against the public key to find the right one.

        Return
        ------
        tuple[int,int]
            the two private ECDSA key candidates
        
        Raises
        ------
        ECDSALatticeAttackError
            raised if something went wrong. The error contains a string with further information.
            Most likely, the lattice attack was not able to compute the private key
            because of an insufficient number of traces.
            You can try adding more traces or setting rebalance to True.
        '''
        balance = lambda KK: KK // 2 if self.rebalance else KK
        if len(self.traces) <= 1: raise ECDSALatticeAttackError('Not enough traces!')
        # compute coeffs
        KK, tt, uu = self._compute_coeffs()
        # construct lattice
        MM = self._fill_lattice(KK, tt, uu)
        # reduce lattice
        MB = MM.LLL()
        # reconstruct private key
        if MB[0, -1] != balance(KK):
            raise ECDSALatticeAttackError('Attack failed!')
        a0 = self._bytes2fn(self.traces[-1].a)
        b0p = self.Fn(MB[0, -2])
        k0 = self.Fn(self._compute_nonce(a0, b0p, int(KK)))
        h0 = self._bytes2fn(self.traces[-1].h)
        r0 = self._bytes2fn(self.traces[-1].r)
        s0 = self._bytes2fn(self.traces[-1].s)
        return self._compute_privkey(k0, h0, r0, s0)

    ####################################
    
    def _set_ec_params(self, ecparams: ECParams) -> bool:
        '''Initializes all internal elliptic curve parameters according to the provided parameters'''
        self.ec_name = ecparams.name
        self.ec_bits = ecparams.bits
        self.pp = ecparams.p
        self.Fp = GF(self.pp)
        self.EE = EllipticCurve(self.Fp, [0, 0, 0, ecparams.a, ecparams.b])
        self.GG = self.EE((ecparams.Gx, ecparams.Gy))
        self.nn = ecparams.n
        self.Fn = GF(self.nn)
        return self.nn == self.GG.order()
    
    def _compute_coeffs(self) -> tuple[int, list[Rational], list[Rational]]:
        '''Computes all coefficients from the given traces'''
        tt = list()
        uu = list()
        if self.MSB: KK = 2**(self.ec_bits - self.known_bits)
        else:        KK = 2**self.known_bits
        trm = self.traces[-1]
        for tri in self.traces[:-1]:
            ti, ui = self._compute_coeff(KK, trm.h, trm.a, trm.r, trm.s, tri.h, tri.a, tri.r, tri.s)
            tt.append(ti)
            uu.append(ui)
            pass
        return KK, tt, uu
    
    def _fill_lattice(self, KK: int, tt: list[int], uu: list[int]) -> Matrix:
        '''Fills the given coefficients into the lattice basis matrix'''
        balance = lambda KK: KK // 2 if self.rebalance else KK
        size = len(tt)
        MM = Matrix(QQ, size + 2)
        for ii, (ti, ui) in enumerate(zip(tt, uu)):
            MM[ii, ii] = self.nn
            MM[-2, ii] = ti
            MM[-1, ii] = ui
            pass
        MM[-2, -2] = 1
        MM[-1, -1] = balance(KK)
        return MM
    
    def _compute_nonce(self, aa: IntMod, bbp: IntMod, KK: int) -> int:
        '''Reconstructs a nonce from the known bits and the computed unknown bits'''
        nonzero = lambda aa: 0       if self.zerobits  else aa
        balance = lambda KK: KK // 2 if self.rebalance else 0
        def msb(aa: IntMod, bb: IntMod) -> IntMod:
            assert not self.zerobits  or (nonzero(aa) == 0) # zerobits implies nonzero to return zero
            if self.MSB:
                return bb + nonzero(aa)
            return 2**self.known_bits * bb + nonzero(aa)
        assert not self.rebalance or (balance(KK) != 0) # rebalance implies balance to return non-zero
        bb = bbp + balance(KK)
        kk = msb(aa, bb)
        return int(kk)
    
    def _compute_privkey(self, kk: IntMod, hh: IntMod, rr: IntMod, ss: IntMod) -> tuple[int, int]:
        '''Computes the pivate ECDSA key candidates from a signature and a known nonce'''
        d0 = lift(( ss * kk - hh) * rr**-1)
        d1 = lift((-ss * kk - hh) * rr**-1)
        return int(d0), int(d1)

    ####################################

    def _compute_coeff(self, KK: int, hm_b: bytes, am_b: bytes, rm_b: bytes, sm_b: bytes, hi_b: bytes, ai_b: bytes, ri_b: bytes, si_b: bytes) -> tuple[int, int]:
        '''Computes a single coefficient'''
        hm, am, rm, sm = self._bytes2fn(hm_b), self._bytes2fn(am_b), self._bytes2fn(rm_b), self._bytes2fn(sm_b)
        hi, ai, ri, si = self._bytes2fn(hi_b), self._bytes2fn(ai_b), self._bytes2fn(ri_b), self._bytes2fn(si_b)
        nonzero = lambda ai, am, ti: 0                   if self.zerobits  else ai + ti * am # ensures that ai and am are zero if test mode enforces it
        msb     = lambda :           1                   if self.MSB       else self.Fn(2)**-(self.known_bits)
        balance = lambda KK, ti:     (ti + 1) *  KK // 2 if self.rebalance else 0
        ti = lift(self.Fn(-1) * si**-1 * sm * ri * rm**-1)
        assert not self.zerobits  or (nonzero(ai, am, ti) == 0) # zerobits implies nonzero to return zero
        assert not self.rebalance or (balance(KK, ti) != 0)     # rebalance implies balance to return non-zero
        ui = msb() * lift(si**-1 * ri * rm**-1 * hm - si**-1 * hi + nonzero(ai, am, ti)) + balance(KK, ti)
        return ti, ui

    ####################################

    def _bytes2int(self, bb: bytes) -> int:
        '''Converts bytes to integer'''
        return int.from_bytes(bb, 'big')
    
    def _bytes2fn(self, bb: bytes) -> IntMod:
        '''Converts bytes to finite field modulo nn'''
        return self.Fn(self._bytes2int(bb))

    def _int2bytes(self, ii: int):
        '''Converts an integer to bytes'''
        return int(ii).to_bytes(self.ec_bits // 8, 'big')

    ####################################
    
    def __repr__(self):
        ''' Returns a representation of this object. '''
        return self.__str__()

    def __str__(self) -> str:
        ''' Returns a string representation of this object. '''
        ans = f"ECDSALatticeAttack(traces={len(self.traces)}, known_bits={self.known_bits}, curve={self.ec_name}, MSB={self.MSB}, rebalance={self.rebalance})"
        return ans
    pass
# END ECDSALatticeAttack
    