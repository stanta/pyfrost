import subprocess
import json
from typing import List, Dict, Any, Tuple

from .abstract import DkgABC, SigningABC, TssProtocolFactory


class BinanceDkg(DkgABC):
    """
    DKG implementation using Binance tss-lib CLI wrapper.
    This is a stub implementation.
    """

    def __init__(self, dkg_id: str, threshold: int, node_id: str, partners: List[str], **kwargs):
        self.dkg_id = dkg_id
        self.threshold = threshold
        self.node_id = node_id
        self.partners = partners
        self.key_type = kwargs.get("key_type", "ETH")
        # We would store state here, e.g., local party data
        print("BinanceDkg Initialized (STUB)")

    def round1(self) -> Dict[str, Any]:
        # In a real implementation, this would call the Go CLI:
        # cmd = f"./tss-cli dkg round1 --dkg-id {self.dkg_id} --threshold {self.threshold} ..."
        # result = subprocess.check_output(cmd, shell=True)
        # return json.loads(result)
        print("BinanceDkg round1 executed (STUB)")
        # Returning dummy data that matches the expected structure
        return {"status": "SUCCESSFUL", "broadcast": {"dummy_data": "round1"}}

    def round2(self, round1_broadcasted_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        print("BinanceDkg round2 executed (STUB)")
        # Dummy data for encrypted messages to partners
        return [{"receiver_id": p, "encrypted_data": "dummy"} for p in self.partners if p != self.node_id]

    def round3(self, round2_encrypted_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        print("BinanceDkg round3 executed (STUB)")
        # Dummy result of the DKG process
        return {
            "status": "SUCCESSFUL",
            "data": {
                "dkg_public_key": "0xdummy_pub_key",
                "public_share": "0xdummy_share",
            },
            "dkg_key_pair": {"share": "dummy_private_share"},
        }


class BinanceSigning(SigningABC):
    """
    Signing implementation using Binance tss-lib CLI wrapper.
    This is a stub implementation.
    """

    def __init__(self, dkg_key: Dict, node_id: str):
        self.dkg_key = dkg_key
        self.node_id = node_id
        print("BinanceSigning Initialized (STUB)")

    def sign(self, nonces_dict: Dict, message: str, nonce_pair: Dict) -> Dict:
        # cmd = f"./tss-cli sign --dkg-key '{json.dumps(self.dkg_key)}' --message {message} ..."
        # result = subprocess.check_output(cmd, shell=True)
        # return json.loads(result)
        print("BinanceSigning sign executed (STUB)")
        return {"signature": "0x_dummy_binance_signature_share"}


class BinanceTssFactory(TssProtocolFactory):
    @staticmethod
    def create_dkg_instance(dkg_id: str, threshold: int, node_id: str, partners: List[str], **kwargs) -> DkgABC:
        return BinanceDkg(dkg_id, threshold, node_id, partners, **kwargs)

    @staticmethod
    def create_signing_instance(dkg_key: Dict, node_id: str) -> SigningABC:
        return BinanceSigning(dkg_key, node_id)

    @staticmethod
    def create_nonces(node_id: int, number_of_nonces: int = 10) -> Tuple[List[Dict], List[Dict]]:
        # This would also call the CLI in a real implementation
        print("BinanceTssFactory create_nonces executed (STUB)")
        dummy_public_nonces = [{"id": node_id, "public_nonce": "dummy_nonce"}] * number_of_nonces
        dummy_private_nonces = [{"private_nonce": "dummy_private"}] * number_of_nonces
        return dummy_public_nonces, dummy_private_nonces

    @staticmethod
    def aggregate_signatures(
        message: str,
        single_signatures: List[Dict[str, int]],
        aggregated_public_nonce: Any,
        group_key: int,
        key_type: str,
    ) -> Dict:
        print("BinanceTssFactory aggregate_signatures executed (STUB)")
        return {"signature": "0x_dummy_aggregated_binance_signature"}

    @staticmethod
    def verify_group_signature(aggregated_signature: Dict) -> bool:
        print("BinanceTssFactory verify_group_signature executed (STUB)")
        return True