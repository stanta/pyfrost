from flask import Blueprint, request, jsonify, abort, current_app
from .decorators import request_handler
from ..dkg import SUPPORTED_PROTOCOLS
import json
from fastecdsa import ecdsa, curve
from fastecdsa.encoding.sec1 import SEC1Encoder
import logging

dkg_bp = Blueprint('dkg', __name__)


@dkg_bp.route("/v1/dkg/round1", methods=["POST"])
@request_handler
def round1():
    node = current_app.node
    data = request.get_json()
    party = data["party"]
    dkg_id = data["dkg_id"]
    threshold = data["threshold"]
    key_type = data["key_type"]
    protocol_type = data.get("protocol_type", "pyfrost")

    if protocol_type not in SUPPORTED_PROTOCOLS:
        abort(400, f"Protocol '{protocol_type}' not supported.")

    assert (
        node.node_id in party
    ), f"This node is not amoung specified party for app {dkg_id}"
    assert threshold <= len(party), f"Threshold must be <= n for Dkg {dkg_id}"
    
    partners = [node_id for node_id in party if node.node_id != node.node_id]
    
    factory = SUPPORTED_PROTOCOLS[protocol_type]
    dkg_instance = factory.create_dkg_instance(
        dkg_id=dkg_id,
        threshold=threshold,
        node_id=node.node_id,
        partners=partners,
        key_type=key_type
    )
    node.key_gens[dkg_id] = dkg_instance
    round1_broadcast_data = node.key_gens[dkg_id].round1()

    broadcast_bytes = json.dumps(round1_broadcast_data, sort_keys=True).encode(
        "utf-8"
    )
    result = {
        "broadcast": round1_broadcast_data,
        "validation": ecdsa.sign(broadcast_bytes, node.private, curve.secp256k1),
        "status": "SUCCESSFUL",
    }
    return result


@dkg_bp.route("/v1/dkg/round2", methods=["POST"])
@request_handler
def round2():
    node = current_app.node
    data = request.get_json()
    dkg_id = data["dkg_id"]
    whole_broadcasted_data = data.get("broadcasted_data")
    broadcasted_data = []
    for node_id, data in whole_broadcasted_data.items():
        # TODO: error handling (if verification failed)
        data_bytes = json.dumps(data["broadcast"]).encode("utf-8")
        validation = data["validation"]
        public_key_code = node.nodes_info.lookup_node(node.node_id)["public_key"]
        public_key = SEC1Encoder.decode_public_key(
            bytes.fromhex(hex(public_key_code).replace("x", "")), curve.secp256k1
        )
        verify_result = ecdsa.verify(
            validation, data_bytes, public_key, curve=curve.secp256k1
        )
        logging.debug(f"Verification of sent data from {node_id}: {verify_result}")
        broadcasted_data.append(data["broadcast"])
    round2_broadcast_data = node.key_gens[dkg_id].round2(broadcasted_data)
    result = {
        "broadcast": round2_broadcast_data,
        "status": "SUCCESSFUL",
    }
    return result


@dkg_bp.route("/v1/dkg/round3", methods=["POST"])
@request_handler
def round3():
    node = current_app.node
    data = request.get_json()
    dkg_id = data["dkg_id"]
    send_data = data["send_data"]

    round3_data = node.key_gens[dkg_id].round3(send_data)
    if round3_data["status"] == "COMPLAINT":
        if dkg_id in node.key_gens:
            del node.key_gens[dkg_id]

    round3_data["validation"] = None
    if round3_data["status"] == "SUCCESSFUL":
        sign_data = json.dumps(round3_data["data"]).encode("utf-8")
        round3_data["validation"] = ecdsa.sign(
            sign_data, node.private, curve.secp256k1
        )
        round3_data["dkg_key_pair"]["key_type"] = node.key_gens[dkg_id].key_type
        node.data_manager.set_key(
            str(round3_data["dkg_key_pair"]["dkg_public_key"]),
            round3_data["dkg_key_pair"],
        )

    result = {
        "data": round3_data["data"],
        "validation": round3_data["validation"],
        "status": round3_data["status"],
    }
    return result
