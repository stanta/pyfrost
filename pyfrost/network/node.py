from flask import Blueprint, request, jsonify, abort
from flasgger import Swagger
from pyfrost.frost import (
    Key,
    KeyGen,
    create_nonces,
    aggregate_signatures,
    verify_group_signature,
)
from pyfrost.crypto_utils import (
    code_to_pub,
    pub_to_addr,
)
from typing import Dict, List
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa import ecdsa, curve
from fastecdsa.point import Point
from .abstract import NodesInfo, DataManager
import json
import logging
import types
import asyncio
import aiohttp
from hashlib import sha256
from enum import Enum
from web3 import Web3
from tronpy import Tron
from tronpy.providers import HTTPProvider
from .models import SigningRequestStatus
from .routes.dkg import dkg_bp
from .routes.signing import signing_bp
from .routes.wallets import wallets_bp
from .routes.signing_requests import signing_requests_bp
from .routes.transactions import transactions_bp
from .routes.health import health_bp


class Node:
    def __init__(
        self,
        data_manager: DataManager,
        node_id: int,
        private: int,
        nodes_info: NodesInfo,
        caller_validator: types.FunctionType,
        data_validator: types.FunctionType,
        eth_rpc_url: str = None,
        tron_rpc_url: str = None,
    ) -> None:
        self.private = private
        self.node_id = str(node_id)
        self.key_gens: Dict[str, KeyGen] = {}
        self.created_wallets: List[str] = []
        self.signing_requests: Dict[str, Dict] = {}

        # Abstracts:
        self.nodes_info: NodesInfo = nodes_info
        self.caller_validator = caller_validator
        self.data_validator = data_validator
        self.data_manager: DataManager = data_manager
        self.w3 = None
        if eth_rpc_url:
            self.w3 = Web3(Web3.HTTPProvider(eth_rpc_url))
            if not self.w3.is_connected():
                raise ConnectionError(
                    f"Failed to connect to Ethereum RPC at {eth_rpc_url}"
                )
        self.tron = None
        if tron_rpc_url:
            provider = HTTPProvider(tron_rpc_url)
            self.tron = Tron(provider=provider)

    def register_blueprints(self, app):
        app.register_blueprint(dkg_bp, url_prefix="/pyfrost")
        app.register_blueprint(signing_bp, url_prefix="/pyfrost")
        app.register_blueprint(wallets_bp, url_prefix="/pyfrost")
        app.register_blueprint(signing_requests_bp, url_prefix="/pyfrost")
        app.register_blueprint(transactions_bp, url_prefix="/pyfrost")
        app.register_blueprint(health_bp, url_prefix="/pyfrost")
        app.node = self  # Attach the node instance to the app context

        if not hasattr(app, 'swagger'):
            app.swagger = Swagger(app)
        self.swagger = app.swagger

    async def _make_request(self, session, node_id, endpoint, data):
        """Helper to make async requests to other nodes."""
        node_info = self.nodes_info.lookup_node(node_id)
        url = f"http://{node_info['host']}:{node_info['port']}{endpoint}"
        logging.debug(f"Making request to {url} with data: {data}")
        async with session.post(url, json=data) as response:
            response.raise_for_status()
            res_json = await response.json()
            logging.debug(f"Got response from {url}: {res_json}")
            return res_json

    async def _orchestrate_signature_creation(
        self, dkg_public_key: str, message: str, party: List[str], key_type: str = 'ETH'
    ) -> Dict:
        """Internal method to orchestrate signature generation."""
        request_id = sha256(message.encode()).hexdigest()
        async with aiohttp.ClientSession() as session:
            # 1. Generate nonces
            nonce_payload = {"number_of_nonces": 1}
            nonce_tasks = [
                self._make_request(
                    session, node_id, "/v1/generate-nonces", nonce_payload
                )
                for node_id in party
            ]
            nonce_results = await asyncio.gather(*nonce_tasks)

            nonces_dict = {
                res["data"][0]["id"]: res["data"][0] for res in nonce_results
            }

            # 2. Get partial signatures
            sign_payload = {
                "dkg_public_key": dkg_public_key,
                "nonces_dict": nonces_dict,
                "data": {"hash": message, "chain": key_type},
                "request_id": request_id,
            }
            sign_tasks = [
                self._make_request(session, node_id, "/v1/sign", sign_payload)
                for node_id in party
            ]
            partial_signatures = await asyncio.gather(*sign_tasks)

            partial_signatures_data = [
                sig["signature_data"] for sig in partial_signatures
            ]

        agg_pub_nonce_code = partial_signatures_data[0]["aggregated_public_nonce"]
        agg_pub_nonce = code_to_pub(agg_pub_nonce_code)

        aggregated_signature = aggregate_signatures(
            message,
            partial_signatures_data,
            agg_pub_nonce,
            int(dkg_public_key, 16),
            partial_signatures_data[0]["key_type"],
        )

        is_valid = verify_group_signature(aggregated_signature)
        if not is_valid:
            raise Exception("Failed to verify aggregated signature.")

        return aggregated_signature
