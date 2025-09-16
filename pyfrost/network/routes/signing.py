from flask import Blueprint, request, jsonify, abort, current_app
from .decorators import request_handler, async_request_handler
from ..dkg import SUPPORTED_PROTOCOLS
from fastecdsa.point import Point
from fastecdsa.encoding.sec1 import SEC1Encoder

signing_bp = Blueprint('signing', __name__)


@signing_bp.route("/v1/sign", methods=["POST"])
@request_handler
def sign():
    node = current_app.node
    data = request.get_json()
    dkg_public_key = data["dkg_public_key"]
    nonces_dict = data["nonces_dict"]
    sa_data = data["data"]
    request_id = data["request_id"]
    chain = data.get("chain", "ETH")
    sa_data['chain'] = chain
    result = node.data_validator(sa_data)
    key_pair = node.data_manager.get_key(str(dkg_public_key))
    if not key_pair:
        abort(404, f"Key {dkg_public_key} not found.")

    protocol_type = key_pair.get("protocol_type", "pyfrost") # Default to pyfrost if not specified
    if protocol_type not in SUPPORTED_PROTOCOLS:
        abort(400, f"Protocol '{protocol_type}' for the key is not supported.")

    factory = SUPPORTED_PROTOCOLS[protocol_type]
    signing_instance = factory.create_signing_instance(key_pair, node.node_id)

    nonce_public_pair = nonces_dict[node.node_id]
    nonce_d_public = nonce_public_pair["public_nonce_d"]
    nonce_e_public = nonce_public_pair["public_nonce_e"]
    nonce_d_private = node.data_manager.get_nonce(str(nonce_d_public))
    nonce_e_private = node.data_manager.get_nonce(str(nonce_e_public))
    nonce = {"nonce_d": nonce_d_private, "nonce_e": nonce_e_private}
    result["signature_data"] = signing_instance.sign(nonces_dict, result["hash"], nonce)
    node.data_manager.remove_nonce(str(nonce_d_public))
    node.data_manager.remove_nonce(str(nonce_e_public))

    result["status"] = "SUCCESSFUL"
    result["request_id"] = request_id
    return result


@signing_bp.route("/v1/generate-nonces", methods=["POST"])
@request_handler
def generate_nonces():
    node = current_app.node
    data = request.get_json()
    number_of_nonces = data["number_of_nonces"]
    protocol_type = data.get("protocol_type", "pyfrost")

    if protocol_type not in SUPPORTED_PROTOCOLS:
        abort(400, f"Protocol '{protocol_type}' not supported.")

    factory = SUPPORTED_PROTOCOLS[protocol_type]
    nonces, save_data = factory.create_nonces(int(node.node_id), number_of_nonces)

    for nonce in save_data:
        nonce_e_public, nonce_e_private = nonce["nonce_e_pair"].popitem()
        node.data_manager.set_nonce(str(nonce_e_public), nonce_e_private)
        nonce_d_public, nonce_d_private = nonce["nonce_d_pair"].popitem()
        node.data_manager.set_nonce(str(nonce_d_public), nonce_d_private)
    result = {
        "data": nonces,
        "status": "SUCCESSFUL",
    }
    return result
