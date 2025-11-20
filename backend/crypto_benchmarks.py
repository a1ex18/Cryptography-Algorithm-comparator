"""Benchmark helpers built on top of the cryptography library."""
from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519

from security import RNG, secure_compare

ProgressCallback = Callable[[str, int, Dict[str, object]], None]


@dataclass(frozen=True)
class BenchmarkStats:
    avg_ns: float
    std_ns: float
    median_ns: float

    @classmethod
    def from_samples(cls, samples: Iterable[int]) -> "BenchmarkStats":
        collected = list(samples)
        if not collected:
            raise ValueError("samples must not be empty")
        avg_ns = statistics.mean(collected)
        std_ns = statistics.pstdev(collected) if len(collected) > 1 else 0.0
        median_ns = statistics.median(collected)
        return cls(avg_ns=avg_ns, std_ns=std_ns, median_ns=median_ns)

    def to_payload(self) -> Dict[str, float]:
        return {
            "avg_ns": self.avg_ns,
            "std_ns": self.std_ns,
            "median_ns": self.median_ns,
        }


class BenchmarkError(RuntimeError):
    """Raised when a benchmark fails to complete."""


_RSA_PADDING_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

_RSA_PADDING_PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)

_EC_CURVES: Dict[str, object] = {
    "secp192r1": ec.SECP192R1(),
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
    "secp521r1": ec.SECP521R1(),
}


def _emit(progress: Optional[ProgressCallback], stage: str, value: int, payload: Optional[Dict[str, object]] = None) -> None:
    if progress:
        progress(stage, value, payload or {})


def benchmark_rsa(
    *,
    bits: int,
    message_size: int,
    repeats: int,
    progress: Optional[ProgressCallback] = None,
) -> Dict[str, object]:
    if bits < 512:
        raise ValueError("RSA key size must be at least 512 bits")
    if message_size <= 0:
        raise ValueError("message_size must be positive")
    if repeats <= 0:
        raise ValueError("repeats must be positive")

    _emit(progress, "started", 0, {"bits": bits, "message_size": message_size})
    keygen_start = time.perf_counter_ns()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    keygen_ns = time.perf_counter_ns() - keygen_start
    public_key = private_key.public_key()
    _emit(progress, "keygen", 25, {"modulus_bits": bits})

    encrypt_samples: list[int] = []
    decrypt_samples: list[int] = []
    sign_samples: list[int] = []
    verify_samples: list[int] = []

    for idx in range(repeats):
        message = RNG.bytes(message_size)
        _emit(progress, "prepare", 30, {"iteration": idx + 1, "total": repeats})

        enc_start = time.perf_counter_ns()
        ciphertext = public_key.encrypt(message, _RSA_PADDING_OAEP)
        encrypt_samples.append(time.perf_counter_ns() - enc_start)

        dec_start = time.perf_counter_ns()
        recovered = private_key.decrypt(ciphertext, _RSA_PADDING_OAEP)
        decrypt_samples.append(time.perf_counter_ns() - dec_start)
        if not secure_compare(recovered, message):
            raise BenchmarkError("RSA decrypt output mismatch")

        sign_start = time.perf_counter_ns()
        signature = private_key.sign(message, _RSA_PADDING_PSS, hashes.SHA256())
        sign_samples.append(time.perf_counter_ns() - sign_start)

        verify_start = time.perf_counter_ns()
        public_key.verify(signature, message, _RSA_PADDING_PSS, hashes.SHA256())
        verify_samples.append(time.perf_counter_ns() - verify_start)

        progress_value = 30 + ((idx + 1) * 70 // repeats)
        _emit(
            progress,
            "iteration",
            min(progress_value, 95),
            {"iteration": idx + 1, "total": repeats},
        )

    result = {
        "keygen_stats": BenchmarkStats.from_samples([keygen_ns]).to_payload(),
        "encrypt_stats": BenchmarkStats.from_samples(encrypt_samples).to_payload(),
        "decrypt_stats": BenchmarkStats.from_samples(decrypt_samples).to_payload(),
        "sign_stats": BenchmarkStats.from_samples(sign_samples).to_payload(),
        "verify_stats": BenchmarkStats.from_samples(verify_samples).to_payload(),
    }

    total_time_ns = keygen_ns + sum(encrypt_samples) + sum(decrypt_samples) + sum(sign_samples) + sum(verify_samples)
    result["total_time_ns"] = total_time_ns
    _emit(progress, "complete", 100, {"total_time_ns": total_time_ns})
    return result


def benchmark_ecdh(
    *,
    curve: str,
    repeats: int,
    progress: Optional[ProgressCallback] = None,
) -> Dict[str, object]:
    if repeats <= 0:
        raise ValueError("repeats must be positive")

    _emit(progress, "started", 0, {"curve": curve, "repeats": repeats})

    if curve.lower() == "x25519":
        def _generate_key():
            return x25519.X25519PrivateKey.generate()

        def _exchange(private_key, peer_public):
            return private_key.exchange(peer_public)

        to_public = lambda priv: priv.public_key()
    else:
        curve_obj = _EC_CURVES.get(curve.lower())
        if curve_obj is None:
            raise ValueError(f"Unsupported curve '{curve}'")

        def _generate_key():
            return ec.generate_private_key(curve_obj)

        def _exchange(private_key, peer_public):
            return private_key.exchange(ec.ECDH(), peer_public)

        to_public = lambda priv: priv.public_key()

    keygen_samples: list[int] = []
    key_pairs = []

    for idx in range(repeats):
        start_ns = time.perf_counter_ns()
        priv_key = _generate_key()
        pub_key = to_public(priv_key)
        keygen_samples.append(time.perf_counter_ns() - start_ns)
        key_pairs.append((priv_key, pub_key))
        _emit(progress, "keygen", 20 + ((idx + 1) * 30 // repeats), {"generated": idx + 1})

    shared_samples: list[int] = []
    for idx in range(repeats):
        left_priv, left_pub = key_pairs[idx]
        right_priv, right_pub = key_pairs[(idx + 1) % repeats]

        left_start = time.perf_counter_ns()
        left_secret = _exchange(left_priv, right_pub)
        left_duration = time.perf_counter_ns() - left_start

        right_start = time.perf_counter_ns()
        right_secret = _exchange(right_priv, left_pub)
        right_duration = time.perf_counter_ns() - right_start

        combined_ns = max(left_duration, right_duration)
        shared_samples.append(combined_ns)

        if not secure_compare(left_secret, right_secret):
            raise BenchmarkError("ECDH derived secrets do not match")

        progress_value = 60 + ((idx + 1) * 35 // repeats)
        _emit(progress, "exchange", min(progress_value, 95), {"completed": idx + 1})

    result = {
        "keygen_stats": BenchmarkStats.from_samples(keygen_samples).to_payload(),
        "shared_stats": BenchmarkStats.from_samples(shared_samples).to_payload(),
    }
    total_time_ns = sum(keygen_samples) + sum(shared_samples)
    result["total_time_ns"] = total_time_ns
    _emit(progress, "complete", 100, {"total_time_ns": total_time_ns})
    return result
