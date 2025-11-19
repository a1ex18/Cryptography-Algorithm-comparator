import hashlib
import secrets
import random
import time
import math
import statistics
from typing import Tuple, Optional, List

def is_probable_prime(n: int, k: int = 8) -> bool:
  
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def gen_prime(bits: int) -> int:
    assert bits >= 2
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) |1
        if is_probable_prime(candidate):
            return candidate
#RSA
def egcd(a: int, b: int) -> Tuple[int,int,int]:
    if b == 0:
        return (a,1,0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

def rsa_keygen(bits: int = 1024) -> Tuple[Tuple[int,int], Tuple[int,int]]:
    e = 65537
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return (n, e), (n, d)

def rsa_encrypt(pub: Tuple[int,int], message: bytes) -> int:
    n, e = pub
    m = int.from_bytes(message, 'big')
    if m >= n:
        raise ValueError("message too large for modulus. Use chunking")
    c = pow(m, e, n)
    return c

def rsa_decrypt(priv: Tuple[int,int], ciphertext: int) -> bytes:
    n, d = priv
    m = pow(ciphertext, d, n)
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, 'big')

def rsa_encrypt_bytes(pub: Tuple[int,int], data: bytes) -> List[int]:
    n, e = pub
    k = (n.bit_length() - 1) // 8 
    if k == 0:
        raise ValueError("modulus too small")
    chunks = []
    for i in range(0, len(data), k):
        chunk = data[i:i+k]
        chunks.append(rsa_encrypt(pub, chunk))
    return chunks

def rsa_decrypt_bytes(priv: Tuple[int,int], chunks: List[int]) -> bytes:
    out = bytearray()
    for c in chunks:
        out.extend(rsa_decrypt(priv, c))
    return bytes(out)

# ECC, ECDH
class Curve:
    def __init__(self, p: int, a: int, b: int, gx: int, gy: int, n: int, name="custom"):
        self.p = p
        self.a = a
        self.b = b
        self.G = (gx, gy)
        self.n = n
        self.name = name

SECP192_TEST = Curve(
    p = 6277101735386680763835789423207666416083908700390324961279,
    a = -3,
    b = 2455155546008943817740293915197451784769108058161191238065,
    gx = 602046282375688656758213480587526111916698976636884684818,
    gy = 174050332293622031404857552280219410364023488927386650641,
    n = 6277101735386680763835789423176059013767194773182842284081,
    name = "secp192r1"
)

def inv_mod(x: int, p: int) -> int:
    return pow(x, p-2, p)

def is_on_curve(point: Optional[Tuple[int,int]], curve: Curve) -> bool:
    if point is None:
        return True
    x, y = point
    p = curve.p
    return (y*y - (x*x*x + curve.a * x + curve.b)) % p == 0

def point_add(p1: Optional[Tuple[int,int]], p2: Optional[Tuple[int,int]], curve: Curve) -> Optional[Tuple[int,int]]:
    if p1 is None: return p2
    if p2 is None: return p1
    x1,y1 = p1
    x2,y2 = p2
    p = curve.p
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if p1 != p2:
        s = ((y2 - y1) * inv_mod((x2 - x1) % p, p)) % p
    else:
        if y1 == 0:
            return None
        s = ((3 * x1 * x1 + curve.a) * inv_mod((2 * y1) % p, p)) % p
    x3 = (s * s - x1 - x2) % p
    y3 = (s * (x1 - x3) - y1) % p
    return (x3, y3)

def scalar_mult(k: int, point: Optional[Tuple[int,int]], curve: Curve) -> Optional[Tuple[int,int]]:

    assert is_on_curve(point, curve)
    if k % curve.n == 0 or point is None:
        return None
    if k < 0:
        return scalar_mult(-k, (point[0], (-point[1]) % curve.p), curve)
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend, curve)
        addend = point_add(addend, addend, curve)
        k >>= 1
    return result

def ecc_keygen(curve: Curve = SECP192_TEST) -> Tuple[int, Tuple[int,int]]:
    d = secrets.randbelow(curve.n - 1) + 1
    Q = scalar_mult(d, curve.G, curve)
    if Q is None:
        raise ValueError("Generated public key is None (invalid scalar multiplication)")
    return d, Q

def ecdh_shared_secret(priv: int, peer_pub: Tuple[int,int], curve: Curve = SECP192_TEST) -> bytes:
    S = scalar_mult(priv, peer_pub, curve)
    if S is None:
        raise ValueError("Invalid shared point")
    x, y = S
    raw = x.to_bytes((x.bit_length()+7)//8, 'big') + y.to_bytes((y.bit_length()+7)//8, 'big')
    return hashlib.sha256(raw).digest()

#sha-256
def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

#BB84
def bb84_simulate(num_qubits: int, channel_error_rate: float = 0.0, reveal_fraction: float = 0.1) -> Tuple[bytes, float]:

    alice_bits = [secrets.randbits(1) for _ in range(num_qubits)]
    alice_bases = [secrets.randbits(1) for _ in range(num_qubits)]
    bob_bases = [secrets.randbits(1) for _ in range(num_qubits)]
    bob_bits = []
    for i in range(num_qubits):
        if alice_bases[i] == bob_bases[i]:
            bit = alice_bits[i]
        else:
            bit = secrets.randbits(1)
        if random.random() < channel_error_rate:
            bit ^= 1
        bob_bits.append(bit)
    # sift
    sifted = [alice_bits[i] for i in range(num_qubits) if alice_bases[i] == bob_bases[i]]
    sifted_bob = [bob_bits[i] for i in range(num_qubits) if alice_bases[i] == bob_bases[i]]
    if len(sifted) == 0:
        return b'', 0.0
    sample_count = max(1, int(len(sifted) * reveal_fraction))
    indices = random.sample(range(len(sifted)), sample_count)
    errors = sum(1 for i in indices if sifted[i] != sifted_bob[i])
    measured_error = errors / sample_count
    final_key_bits = [sifted[i] for i in range(len(sifted)) if i not in set(indices)]
    b = 0
    out = bytearray()
    for i, bit in enumerate(final_key_bits):
        b = (b << 1) | bit
        if (i % 8) == 7:
            out.append(b)
            b = 0
    # leftover
    rem = len(final_key_bits) % 8
    if rem:
        out.append(b << (8 - rem))
    return bytes(out), measured_error

def bench_rsa(bits: int, msg_size: int, repeats: int = 3):
    print(f"\n--- RSA {bits}-bit | message {msg_size} bytes | repeats {repeats} ---")
    t = time.perf_counter()
    pub, priv = rsa_keygen(bits)
    gen_time = (time.perf_counter() - t)
    chunks = []
    print(f"Keygen time: {gen_time:.4f} s")
    msg = secrets.token_bytes(msg_size)
    t = time.perf_counter()
    for _ in range(repeats):
        chunks = rsa_encrypt_bytes(pub, msg)
    enc_time = (time.perf_counter() - t) / repeats
    t = time.perf_counter()
    for _ in range(repeats):
        recovered = rsa_decrypt_bytes(priv, chunks)
    dec_time = (time.perf_counter() - t) / repeats
    print(f"Avg encrypt time: {enc_time:.4f} s | Avg decrypt time: {dec_time:.4f} s")
    return {"keygen": gen_time, "encrypt": enc_time, "decrypt": dec_time}

def bench_ecc(curve: Curve, repeats: int = 50):
    print(f"\n--- ECC (ECDH) on curve {curve.name} | repeats {repeats} ---")
    t = time.perf_counter()
    pairs = []
    for _ in range(repeats):
        pairs.append(ecc_keygen(curve))
    keygen_time = (time.perf_counter() - t) / repeats
    print(f"Avg keygen time: {keygen_time:.6f} s")
    # ECDH shared secret derivation
    t = time.perf_counter()
    for i in range(repeats):
        d1, Q1 = pairs[i]
        d2, Q2 = pairs[(i+1) % repeats]
        s1 = ecdh_shared_secret(d1, Q2, curve)
        s2 = ecdh_shared_secret(d2, Q1, curve)
        assert s1 == s2
    shared_time = (time.perf_counter() - t) / repeats
    print(f"Avg shared-secret derivation time: {shared_time:.6f} s")
    return {"keygen": keygen_time, "shared": shared_time}

def bench_sha256(sizes: List[int], repeats: int = 50):
    results = {}
    for s in sizes:
        t = time.perf_counter()
        for _ in range(repeats):
            sha256_hash(secrets.token_bytes(s))
        elapsed = (time.perf_counter() - t) / repeats
        results[s] = elapsed
        print(f"SHA-256 | {s} bytes | Avg time: {elapsed*1e3:.6f} ms")
    return results

def bench_bb84(qubit_counts: List[int], repeats: int = 10, error_rate: float = 0.0):
    results = {}
    for q in qubit_counts:
        times = []
        errs = []
        for _ in range(repeats):
            t0 = time.perf_counter()
            key, err = bb84_simulate(q, channel_error_rate=error_rate)
            t1 = time.perf_counter()
            times.append(t1 - t0)
            errs.append(err)
        results[q] = {"avg_time": statistics.mean(times), "avg_error": statistics.mean(errs)}
        print(f"BB84 | {q} qubits | Avg time: {results[q]['avg_time']:.6f} s | Avg measured error: {results[q]['avg_error']:.4f}")
    return results

def main():
    print("Crypto benchmark demo (RSA, ECC (ECDH), SHA-256, BB84 simulation)")
    
    rsa_results = bench_rsa(bits=1024, msg_size=128, repeats=4) 
    ecc_results = bench_ecc(SECP192_TEST, repeats=10)
   
    sha_results = bench_sha256([128, 256, 1024], repeats=100)
  
    bb84_results = bench_bb84([256, 1024], repeats=5, error_rate=0.01)
    # Summary print
    print("\n=== Summary ===")
    print("RSA:", rsa_results)
    print("ECC:", ecc_results)
    print("SHA-256:", {k: f"{v*1e3:.3f} ms" for k,v in sha_results.items()})
    print("BB84:", bb84_results)

if __name__ == "__main__":
    main()
