from flask import Blueprint, request, jsonify, abort, current_app
from .decorators import request_handler, async_request_handler
from pyfrost.frost import Key, create_nonces
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
    result = node.data_validator(sa_data)
    key_pair = node.data_manager.get_key(str(dkg_public_key))
    # TODO: Must remove
    if isinstance(key_pair["dkg_public_key"], Point):
        comp_pub = SEC1Encoder.encode_public_key(key_pair["dkg_public_key"], True)
        key_pair["dkg_public_key"] = int(comp_pub.hex(), 16)
    key = Key(key_pair, node.node_id)

    nonce_public_pair = nonces_dict[node.node_id]
    nonce_d_public = nonce_public_pair["public_nonce_d"]
    nonce_e_public = nonce_public_pair["public_nonce_e"]
    nonce_d_private = node.data_manager.get_nonce(str(nonce_d_public))
    nonce_e_private = node.data_manager.get_nonce(str(nonce_e_public))
    nonce = {"nonce_d": nonce_d_private, "nonce_e": nonce_e_private}
    result["signature_data"] = key.sign(nonces_dict, result["hash"], nonce)
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
    nonces, save_data = create_nonces(int(node.node_id), number_of_nonces)
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
