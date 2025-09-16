from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple


class DkgABC(ABC):
    """
    Abstract Base Class for the Distributed Key Generation (DKG) process.
    It defines the interface for the multi-round key generation protocol.
    """

    @abstractmethod
    def __init__(self, dkg_id: str, threshold: int, node_id: str, partners: List[str], **kwargs):
        pass

    @abstractmethod
    def round1(self) -> Dict[str, Any]:
        """
        Executes the first round of the DKG protocol.
        Returns:
            A dictionary containing the data to be broadcasted to other participants.
        """
        pass

    @abstractmethod
    def round2(self, round1_broadcasted_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Executes the second round of the DKG protocol using data from the first round.
        Args:
            round1_broadcasted_data: A list of broadcasted data from all participants in round 1.
        Returns:
            A list of encrypted data to be sent to each participant.
        """
        pass

    @abstractmethod
    def round3(self, round2_encrypted_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes the final round of the DKG protocol to generate the key share.
        Args:
            round2_encrypted_data: A list of encrypted data received from other participants.
        Returns:
            A dictionary containing the result of the DKG process, including the public key and key share.
        """
        pass


class SigningABC(ABC):
    """
    Abstract Base Class for the Signing process.
    It defines the interface for creating a signature share.
    """

    @abstractmethod
    def __init__(self, dkg_key: Dict, node_id: str):
        pass

    @abstractmethod
    def sign(self, nonces_dict: Dict, message: str, nonce_pair: Dict) -> Dict:
        """
        Generates a signature share for a given message.
        Args:
            nonces_dict: A dictionary of public nonces from all participants.
            message: The message to be signed (as a hex string).
            nonce_pair: The private nonce pair for the current participant.
        Returns:
            A dictionary containing the signature share.
        """
        pass


class TssProtocolFactory(ABC):
    """
    Abstract factory to create DKG and Signing instances and provide static
    methods for protocol-specific operations.
    """

    @staticmethod
    @abstractmethod
    def create_dkg_instance(dkg_id: str, threshold: int, node_id: str, partners: List[str], **kwargs) -> DkgABC:
        """Creates an instance of a DKG protocol implementation."""
        pass

    @staticmethod
    @abstractmethod
    def create_signing_instance(dkg_key: Dict, node_id: str) -> SigningABC:
        """Creates an instance of a Signing protocol implementation."""
        pass

    @staticmethod
    @abstractmethod
    def create_nonces(node_id: int, number_of_nonces: int = 10) -> Tuple[List[Dict], List[Dict]]:
        """Creates public and private nonces for the signing process."""
        pass

    @staticmethod
    @abstractmethod
    def aggregate_signatures(
        message: str,
        single_signatures: List[Dict[str, int]],
        aggregated_public_nonce: Any,
        group_key: int,
        key_type: str,
    ) -> Dict:
        """Aggregates individual signature shares into a final group signature."""
        pass

    @staticmethod
    @abstractmethod
    def verify_group_signature(aggregated_signature: Dict) -> bool:
        """Verifies the aggregated group signature."""
        pass