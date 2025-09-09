from hashlib import sha256
from typing import Dict

from fastecdsa.point import Point

from pyfrost.crypto_utils import (
    pub_to_addr,
    N,
    code_to_pub,
    ecurve,
    pub_decompress,
)


def tron_challenge(
    group_pub_key: Dict, message: str, aggregated_nonce: str | Point
) -> bytes:
    if isinstance(aggregated_nonce, Point):
        aggregated_nonce = pub_to_addr(aggregated_nonce)

    # Handle different message formats
    if message.startswith('0x'):
        # Remove 0x prefix and decode hex
        message_bytes = bytes.fromhex(message[2:])
    elif len(message) == 64 and all(c in '0123456789abcdefABCDEF' for c in message):
        # 64-character hex string (32 bytes) - decode as hex
        message_bytes = bytes.fromhex(message)
    else:
        # Regular string message
        message_bytes = message.encode()

    return sha256(message_bytes).digest()


def tron_generate_signature_share(share, coef, challenge, nonce_d, nonce_e, row):
    signature_share = (
        nonce_d
        + nonce_e * int.from_bytes(row, "big")
        - coef * share * int.from_bytes(challenge, "big")
    ) % N
    return signature_share


def tron_verify_single_sign(coef, challenge, public_nonce, signature_data):
    challenge_int = int.from_bytes(challenge, "big")
    point1 = public_nonce - (
        challenge_int * coef * code_to_pub(signature_data["public_key_share"])
    )
    point2 = signature_data["single_signature"]["signature"] * ecurve.G
    return point1 == point2


def tron_verify_group_sign(group_pub_key, message, aggregated_signature):
    challenge = tron_challenge(
        group_pub_key, message, aggregated_signature["nonce"]
    )
    challenge_int = int.from_bytes(challenge, "big")
    # Calculate the point
    point = (aggregated_signature["signature"] * ecurve.G) + (
        challenge_int * pub_decompress(aggregated_signature["public_key"])
    )
    return aggregated_signature["nonce"] == pub_to_addr(point)