from typing import List, Dict, Any, Tuple
from fastecdsa.point import Point

from .abstract import DkgABC, SigningABC, TssProtocolFactory
from ..frost_legacy import (
    KeyGen,
    Key,
    create_nonces as frost_create_nonces,
    aggregate_signatures as frost_aggregate_signatures,
    verify_group_signature as frost_verify_group_signature,
)


class PyfrostDkg(DkgABC):
    def __init__(self, dkg_id: str, threshold: int, node_id: str, partners: List[str], **kwargs):
        self.keygen = KeyGen(
            dkg_id=dkg_id,
            threshold=threshold,
            node_id=node_id,
            partners=partners,
            key_type=kwargs.get("key_type", "ETH"),
        )

    def round1(self) -> Dict[str, Any]:
        return self.keygen.round1()

    def round2(self, round1_broadcasted_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self.keygen.round2(round1_broadcasted_data)

    def round3(self, round2_encrypted_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self.keygen.round3(round2_encrypted_data)


class PyfrostSigning(SigningABC):
    def __init__(self, dkg_key: Dict, node_id: str):
        self.key = Key(dkg_key, node_id)

    def sign(self, nonces_dict: Dict, message: str, nonce_pair: Dict) -> Dict:
        return self.key.sign(nonces_dict, message, nonce_pair)


class PyfrostFROSTFactory(TssProtocolFactory):
    @staticmethod
    def create_dkg_instance(dkg_id: str, threshold: int, node_id: str, partners: List[str], **kwargs) -> DkgABC:
        return PyfrostDkg(dkg_id, threshold, node_id, partners, **kwargs)

    @staticmethod
    def create_signing_instance(dkg_key: Dict, node_id: str) -> SigningABC:
        return PyfrostSigning(dkg_key, node_id)

    @staticmethod
    def create_nonces(node_id: int, number_of_nonces: int = 10) -> Tuple[List[Dict], List[Dict]]:
        return frost_create_nonces(node_id, number_of_nonces)

    @staticmethod
    def aggregate_signatures(
        message: str,
        single_signatures: List[Dict[str, int]],
        aggregated_public_nonce: Point,
        group_key: int,
        key_type: str,
    ) -> Dict:
        return frost_aggregate_signatures(
            message, single_signatures, aggregated_public_nonce, group_key, key_type
        )

    @staticmethod
    def verify_group_signature(aggregated_signature: Dict) -> bool:
        return frost_verify_group_signature(aggregated_signature)