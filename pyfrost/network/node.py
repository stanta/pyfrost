from flask import Blueprint, request, jsonify, abort
from flasgger import Swagger, swag_from
from functools import wraps
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
from eth_utils import keccak
from rlp import encode as rlp_encode
from werkzeug.exceptions import HTTPException


class SigningRequestStatus(Enum):
    PENDING = "PENDING"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"


def async_request_handler(func):
    @wraps(func)
    async def wrapper(self, *args, **kwargs):
        route_path = request.url_rule.rule if request.url_rule else None
        if not self.caller_validator(request.remote_addr, route_path):
            abort(403)
        try:
            if request.method in ['POST', 'PUT'] and not request.is_json:
                logging.warning(f"Request from {request.remote_addr} to {route_path} has incorrect Content-Type: {request.content_type}")
            logging.debug(
                f"{request.remote_addr}{route_path} Got message: {request.get_json(silent=True)}"
            )
            result = await func(self, *args, **kwargs)
            logging.debug(
                f"{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}"
            )
            return jsonify(result), 200
        except HTTPException as e:
            # Re-raise HTTP exceptions (like aborts) so Flask can handle them
            raise e
        except Exception as e:
            logging.error(
                f"Flask async handler => Exception occurred: {type(e).__name__}: {e}",
                exc_info=True,
            )
            return (
                jsonify({"error": f"{type(e).__name__}: {e}", "status": "ERROR"}),
                500,
            )

    return wrapper


def request_handler(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        route_path = request.url_rule.rule if request.url_rule else None
        if not self.caller_validator(request.remote_addr, route_path):
            abort(403)
        try:
            if request.method in ['POST', 'PUT'] and not request.is_json:
                logging.warning(f"Request from {request.remote_addr} to {route_path} has incorrect Content-Type: {request.content_type}")
            logging.debug(
                f"{request.remote_addr}{route_path} Got message: {request.get_json(silent=True)}"
            )
            result: Dict = func(self, *args, **kwargs)
            to_sign = json.dumps(result, sort_keys=True).encode("utf-8")
            result["node_signature"] = ecdsa.sign(
                to_sign, self.private, curve.secp256k1
            )
            logging.debug(
                f"{request.remote_addr}{route_path} Sent message: {json.dumps(result, indent=4)}"
            )
            return jsonify(result), 200
        except Exception as e:
            logging.error(
                f"Flask round1 handler => Exception occurred: {type(e).__name__}: {e}",
                exc_info=True,  # This will include the stack trace in the log
            )
            return jsonify(
                {"error": f"{type(e).__name__}: {e}", "status": "ERROR"}
            ), 500

    return wrapper


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
    ) -> None:
        self.blueprint = Blueprint("pyfrost", __name__)
        self.swagger = None  # Will be initialized in Flask app context
        
        # Swagger UI setup (to be called in Flask app context)
        def register_swagger(app):
            if not hasattr(app, 'swagger'):
                app.swagger = Swagger(app)
            self.swagger = app.swagger
        self.register_swagger = register_swagger
        self.private = private
        self.node_id = str(node_id)
        self.key_gens: Dict[str, KeyGen] = {}
        self.created_wallets: List[str] = []
        self.signing_requests: Dict[str, Dict] = {}

        # TODO: Check validator functions if it cannot get as input. and just use in decorator.

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

        # Adding routes:
        self.blueprint.route("/v1/dkg/round1", methods=["POST"])(self.round1)
        self.blueprint.route("/v1/dkg/round2", methods=["POST"])(self.round2)
        self.blueprint.route("/v1/dkg/round3", methods=["POST"])(self.round3)
        self.blueprint.route("/v1/sign", methods=["POST"])(self.sign)
        self.blueprint.route("/v1/generate-nonces", methods=["POST"])(
            self.generate_nonces
        )
        # New orchestrator routes
        self.blueprint.route("/v1/wallets", methods=["POST"])(self.create_wallet)
        self.blueprint.route("/v1/wallets", methods=["GET"])(self.list_wallets)
        self.blueprint.route("/v1/wallets/<dkg_public_key>", methods=["GET"])(
            self.get_wallet_info
        )
        self.blueprint.route("/v1/signing-requests", methods=["POST"])(
            self.create_signing_request
        )
        self.blueprint.route(
            "/v1/signing-requests/<request_id>", methods=["GET"]
        )(self.get_signing_request_details)
        self.blueprint.route(
            "/v1/signing-requests/<request_id>/execute", methods=["POST"]
        )(self.execute_signing_request)
        self.blueprint.route(
            "/v1/signing-requests/<request_id>/reject", methods=["POST"]
        )(self.reject_signing_request)
        self.blueprint.route(
            "/v1/wallets/<dkg_public_key>/transactions", methods=["POST"]
        )(self.send_eth_transaction)
        
        # Health check endpoint (no IP validation required)
        self.blueprint.route("/health", methods=["GET"])(self.health_check)

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
        self, dkg_public_key: str, message: str, party: List[str]
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
                "data": {"hash": message},
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

    @async_request_handler
    async def create_wallet(self):
        """
        Orchestrates the DKG process to create a new wallet.
        ---
        tags:
          - Wallets
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                properties:
                  party:
                    type: array
                    items:
                      type: string
                    description: List of node IDs participating in DKG.
                  threshold:
                    type: integer
                    description: Minimum number of nodes required to sign.
                  key_type:
                    type: string
                    description: Type of key to generate (e.g., ETH).
                  dkg_id:
                    type: string
                    description: Optional DKG session ID.
        responses:
          200:
            description: Wallet created successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    dkg_public_key:
                      type: string
                      description: Public key of the created wallet.
                    status:
                      type: string
                      example: SUCCESSFUL
        """
        data = request.get_json()
        party = data["party"]
        threshold = data["threshold"]
        key_type = data.get("key_type", "ETH")
        dkg_id = data.get(
            "dkg_id",
            sha256(
                json.dumps(party, sort_keys=True).encode()
                + str(threshold).encode()
            ).hexdigest(),
        )

        async with aiohttp.ClientSession() as session:
            # Round 1
            round1_payload = {
                "party": party,
                "dkg_id": dkg_id,
                "threshold": threshold,
                "key_type": key_type,
            }
            round1_tasks = [
                self._make_request(session, node_id, "/v1/dkg/round1", round1_payload)
                for node_id in party
            ]
            round1_results = await asyncio.gather(*round1_tasks)

            broadcasted_data_r1 = {
                res["broadcast"]["sender_id"]: res for res in round1_results
            }

            # Round 2
            round2_payload = {"dkg_id": dkg_id, "broadcasted_data": broadcasted_data_r1}
            round2_tasks = [
                self._make_request(session, node_id, "/v1/dkg/round2", round2_payload)
                for node_id in party
            ]
            round2_results = await asyncio.gather(*round2_tasks)

            send_data_r3 = {node_id: [] for node_id in party}
            for res in round2_results:
                for item in res["broadcast"]:
                    send_data_r3[item["receiver_id"]].append(item)

            # Round 3
            round3_tasks = []
            for node_id in party:
                payload = {"dkg_id": dkg_id, "send_data": send_data_r3[node_id]}
                round3_tasks.append(
                    self._make_request(session, node_id, "/v1/dkg/round3", payload)
                )

            round3_results = await asyncio.gather(*round3_tasks)

        final_pub_key = round3_results[0]["data"]["dkg_public_key"]
        if final_pub_key not in self.created_wallets:
            self.created_wallets.append(final_pub_key)

        return {"dkg_public_key": final_pub_key, "status": "SUCCESSFUL"}

    @async_request_handler
    async def list_wallets(self):
        """
        Lists the public keys of all created wallets.
        ---
        tags:
          - Wallets
        responses:
          200:
            description: List of wallets
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    wallets:
                      type: array
                      items:
                        type: object
                        properties:
                          dkg_public_key:
                            type: string
                            description: Public key of the wallet.
                          has_local_share:
                            type: boolean
                            description: Whether the node has a local share of the wallet.
                          key_type:
                            type: string
                            description: Type of key (if available).
                    status:
                      type: string
                      example: SUCCESSFUL
        """
        wallets_with_details = []
        for pub_key in self.created_wallets:
            details = {"dkg_public_key": pub_key}
            try:
                key_data = self.data_manager.get_key(pub_key)
                if key_data:
                    details["has_local_share"] = True
                    details["key_type"] = key_data.get("key_type")
                else:
                    details["has_local_share"] = False
            except Exception:  # Assuming get_key might fail if key not found
                details["has_local_share"] = False
            wallets_with_details.append(details)

        return {"wallets": wallets_with_details, "status": "SUCCESSFUL"}

    @async_request_handler
    async def get_wallet_info(self, dkg_public_key):
        """
        Gets detailed information about a single wallet.
        ---
        tags:
          - Wallets
        parameters:
          - name: dkg_public_key
            in: path
            required: true
            schema:
              type: string
            description: Public key of the wallet.
        responses:
          200:
            description: Wallet details
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    wallet_info:
                      type: object
                      properties:
                        dkg_public_key:
                          type: string
                        has_local_share:
                          type: boolean
                        key_type:
                          type: string
                    status:
                      type: string
                      example: SUCCESSFUL
        """
        if dkg_public_key not in self.created_wallets:
            abort(404, "Wallet not found")

        details = {"dkg_public_key": dkg_public_key}
        try:
            key_data = self.data_manager.get_key(dkg_public_key)
            if key_data:
                details["has_local_share"] = True
                details["key_type"] = key_data.get("key_type")
            else:
                details["has_local_share"] = False
        except Exception:
            details["has_local_share"] = False

        return {"wallet_info": details, "status": "SUCCESSFUL"}

    @async_request_handler
    async def create_signing_request(self):
        """
        Creates a signing request and stores it for later execution.
        ---
        tags:
          - Signing Requests
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                properties:
                  dkg_public_key:
                    type: string
                    description: Public key of the wallet to use for signing.
                  message:
                    type: string
                    description: Message to sign.
                  party:
                    type: array
                    items:
                      type: string
                    description: List of node IDs participating in signing.
                  request_id:
                    type: string
                    description: Optional request ID.
        responses:
          200:
            description: Signing request created
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    request_id:
                      type: string
                    status:
                      type: string
                      example: PENDING
        """
        data = request.get_json()
        dkg_public_key = data["dkg_public_key"]
        message = data["message"]
        party = data["party"]
        request_id = data.get("request_id", sha256(message.encode()).hexdigest())

        if request_id in self.signing_requests:
            abort(409, f"Signing request with ID {request_id} already exists.")

        self.signing_requests[request_id] = {
            "dkg_public_key": dkg_public_key,
            "message": message,
            "party": party,
            "status": SigningRequestStatus.PENDING.value,
            "signature_data": None,
        }

        return {"request_id": request_id, "status": "PENDING"}

    @async_request_handler
    async def get_signing_request_details(self, request_id):
        """
        Retrieves details for a specific signing request.
        ---
        tags:
          - Signing Requests
        parameters:
          - name: request_id
            in: path
            required: true
            schema:
              type: string
            description: ID of the signing request.
        responses:
          200:
            description: Signing request details
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    signing_request:
                      type: object
                    status:
                      type: string
        """
        signing_request = self.signing_requests.get(request_id)
        if not signing_request:
            abort(404, "Signing request not found")
        return {"signing_request": signing_request}

    @async_request_handler
    async def execute_signing_request(self, request_id):
        """
        Executes a pending signing request.
        ---
        tags:
          - Signing Requests
        parameters:
          - name: request_id
            in: path
            required: true
            schema:
              type: string
            description: ID of the signing request.
        responses:
          200:
            description: Signing request executed
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    request_id:
                      type: string
                    signature_data:
                      type: object
                    status:
                      type: string
                      example: EXECUTED
        """
        signing_request = self.signing_requests.get(request_id)
        if not signing_request:
            abort(404, "Signing request not found")
        if signing_request["status"] != SigningRequestStatus.PENDING.value:
            abort(
                400,
                f"Signing request is not in PENDING state, but in {signing_request['status']}",
            )

        signature = await self._orchestrate_signature_creation(
            signing_request["dkg_public_key"],
            signing_request["message"],
            signing_request["party"],
        )

        signing_request["status"] = SigningRequestStatus.EXECUTED.value
        signing_request["signature_data"] = signature

        return {
            "request_id": request_id,
            "signature_data": signature,
            "status": "EXECUTED",
        }

    @async_request_handler
    async def reject_signing_request(self, request_id):
        """
        Rejects a pending signing request.
        ---
        tags:
          - Signing Requests
        parameters:
          - name: request_id
            in: path
            required: true
            schema:
              type: string
            description: ID of the signing request.
        responses:
          200:
            description: Signing request rejected
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    request_id:
                      type: string
                    status:
                      type: string
                      example: REJECTED
        """
        signing_request = self.signing_requests.get(request_id)
        if not signing_request:
            abort(404, "Signing request not found")
        if signing_request["status"] != SigningRequestStatus.PENDING.value:
            abort(400, "Can only reject a PENDING signing request.")

        signing_request["status"] = SigningRequestStatus.REJECTED.value
        return {"request_id": request_id, "status": "REJECTED"}

    @async_request_handler
    async def send_eth_transaction(self, dkg_public_key):
        """
        Creates, signs, and sends an Ethereum transaction using the specified MPC wallet.
        """
        if not self.w3:
            abort(500, "Ethereum RPC URL not configured for this node.")

        data = request.get_json()
        to_address = data["to"]
        value_in_eth = data["value_in_eth"]
        party = data["party"]

        # 1. Prepare transaction data
        from_address_point = code_to_pub(int(dkg_public_key, 16))
        from_address = pub_to_addr(from_address_point)

        tx_data = {
            "to": self.w3.to_checksum_address(to_address),
            "value": self.w3.to_wei(value_in_eth, "ether"),
            "gas": 21000,
            "gasPrice": self.w3.eth.gas_price,
            "nonce": self.w3.eth.get_transaction_count(from_address),
            "chainId": self.w3.eth.chain_id,
        }

        # 2. Hash the transaction for signing
        # Note: web3.py's Transaction object handles the RLP encoding internally
        tx_object = self.w3.eth.account._prepare_transaction(tx_data)
        tx_hash_to_sign = tx_object.hash.hex()

        # 3. Orchestrate MPC signature
        mpc_signature = await self._orchestrate_signature_creation(
            dkg_public_key, tx_hash_to_sign, party
        )

        # 4. Assemble the final signed transaction
        public_nonce_point = code_to_pub(int(mpc_signature['public_nonce'], 16))
        v = 27 + (public_nonce_point.y % 2)
        r = public_nonce_point.x
        s = mpc_signature['signature']
        
        encoded_tx = self.w3.eth.account._create_transaction_with_signature(tx_object, (v, r, s))

        # 5. Send the transaction to the blockchain
        sent_tx_hash = self.w3.eth.send_raw_transaction(encoded_tx.rawTransaction)

        return {"status": "SUCCESSFUL", "tx_hash": "0x" + sent_tx_hash.hex()}

    @request_handler
    def round1(self):
        data = request.get_json()
        party = data["party"]
        dkg_id = data["dkg_id"]
        threshold = data["threshold"]
        key_type = data["key_type"]
        assert (
            self.node_id in party
        ), f"This node is not amoung specified party for app {dkg_id}"
        assert threshold <= len(party), f"Threshold must be <= n for Dkg {dkg_id}"
        partners = [node_id for node_id in party if self.node_id != node_id]
        self.key_gens[dkg_id] = KeyGen(
            dkg_id, threshold, self.node_id, partners, key_type=key_type
        )
        round1_broadcast_data = self.key_gens[dkg_id].round1()

        broadcast_bytes = json.dumps(round1_broadcast_data, sort_keys=True).encode(
            "utf-8"
        )
        result = {
            "broadcast": round1_broadcast_data,
            "validation": ecdsa.sign(broadcast_bytes, self.private, curve.secp256k1),
            "status": "SUCCESSFUL",
        }
        return result

    @request_handler
    def round2(self):
        data = request.get_json()
        dkg_id = data["dkg_id"]
        whole_broadcasted_data: Dict = data.get("broadcasted_data")
        broadcasted_data = []
        for node_id, data in whole_broadcasted_data.items():
            # TODO: error handling (if verification failed)
            data_bytes = json.dumps(data["broadcast"]).encode("utf-8")
            validation = data["validation"]
            public_key_code = self.nodes_info.lookup_node(self.node_id)["public_key"]
            public_key = SEC1Encoder.decode_public_key(
                bytes.fromhex(hex(public_key_code).replace("x", "")), curve.secp256k1
            )
            verify_result = ecdsa.verify(
                validation, data_bytes, public_key, curve=curve.secp256k1
            )
            logging.debug(f"Verification of sent data from {node_id}: {verify_result}")
            broadcasted_data.append(data["broadcast"])
        round2_broadcast_data = self.key_gens[dkg_id].round2(broadcasted_data)
        result = {
            "broadcast": round2_broadcast_data,
            "status": "SUCCESSFUL",
        }
        return result

    @request_handler
    def round3(self):
        data = request.get_json()
        dkg_id = data["dkg_id"]
        send_data = data["send_data"]

        round3_data = self.key_gens[dkg_id].round3(send_data)
        if round3_data["status"] == "COMPLAINT":
            if dkg_id in self.key_gens:
                del self.key_gens[dkg_id]

        round3_data["validation"] = None
        if round3_data["status"] == "SUCCESSFUL":
            sign_data = json.dumps(round3_data["data"]).encode("utf-8")
            round3_data["validation"] = ecdsa.sign(
                sign_data, self.private, curve.secp256k1
            )
            round3_data["dkg_key_pair"]["key_type"] = self.key_gens[dkg_id].key_type
            self.data_manager.set_key(
                str(round3_data["dkg_key_pair"]["dkg_public_key"]),
                round3_data["dkg_key_pair"],
            )

        result = {
            "data": round3_data["data"],
            "validation": round3_data["validation"],
            "status": round3_data["status"],
        }
        return result

    @request_handler
    def sign(self):
        data = request.get_json()
        dkg_public_key = data["dkg_public_key"]
        nonces_dict = data["nonces_dict"]
        sa_data = data["data"]
        request_id = data["request_id"]
        result = self.data_validator(sa_data)
        key_pair = self.data_manager.get_key(str(dkg_public_key))
        # TODO: Must remove
        if isinstance(key_pair["dkg_public_key"], Point):
            comp_pub = SEC1Encoder.encode_public_key(key_pair["dkg_public_key"], True)
            key_pair["dkg_public_key"] = int(comp_pub.hex(), 16)
        key = Key(key_pair, self.node_id)

        nonce_public_pair = nonces_dict[self.node_id]
        nonce_d_public = nonce_public_pair["public_nonce_d"]
        nonce_e_public = nonce_public_pair["public_nonce_e"]
        nonce_d_private = self.data_manager.get_nonce(str(nonce_d_public))
        nonce_e_private = self.data_manager.get_nonce(str(nonce_e_public))
        nonce = {"nonce_d": nonce_d_private, "nonce_e": nonce_e_private}
        result["signature_data"] = key.sign(nonces_dict, result["hash"], nonce)
        self.data_manager.remove_nonce(str(nonce_d_public))
        self.data_manager.remove_nonce(str(nonce_e_public))

        result["status"] = "SUCCESSFUL"
        result["request_id"] = request_id
        return result

    @request_handler
    def generate_nonces(self):
        data = request.get_json()
        number_of_nonces = data["number_of_nonces"]
        nonces, save_data = create_nonces(int(self.node_id), number_of_nonces)
        for nonce in save_data:
            nonce_e_public, nonce_e_private = nonce["nonce_e_pair"].popitem()
            self.data_manager.set_nonce(str(nonce_e_public), nonce_e_private)
            nonce_d_public, nonce_d_private = nonce["nonce_d_pair"].popitem()
            self.data_manager.set_nonce(str(nonce_d_public), nonce_d_private)
        result = {
            "data": nonces,
            "status": "SUCCESSFUL",
        }
        return result

    def health_check(self):
        """
        Simple health check endpoint for Docker health checks.
        Does not require IP validation.
        ---
        tags:
          - Health
        responses:
          200:
            description: Service is healthy
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    status:
                      type: string
                      example: healthy
                    node_id:
                      type: string
                      example: "1"
        """
        return jsonify({"status": "healthy", "node_id": self.node_id}), 200
