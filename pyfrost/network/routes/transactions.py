from flask import Blueprint, request, jsonify, abort, current_app
from .decorators import async_request_handler
from pyfrost.crypto_utils import code_to_pub, pub_to_addr
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa.curve import secp256k1 as ecurve

transactions_bp = Blueprint('transactions', __name__)


@transactions_bp.route(
    "/v1/wallets/<dkg_public_key>/transactions", methods=["POST"]
)
@async_request_handler
async def send_eth_transaction(dkg_public_key):
    """
    Creates, signs, and sends an Ethereum transaction using the specified MPC wallet.
    """
    node = current_app.node
    if not node.w3:
        abort(500, "Ethereum RPC URL not configured for this node.")

    data = request.get_json()
    to_address = data["to"]
    value_in_eth = data["value_in_eth"]
    party = data["party"]

    # 1. Prepare transaction data
    from_address_point = code_to_pub(int(dkg_public_key, 16))
    from_address = pub_to_addr(from_address_point)

    tx_data = {
        "to": node.w3.to_checksum_address(to_address),
        "value": node.w3.to_wei(value_in_eth, "ether"),
        "gas": 21000,
        "gasPrice": node.w3.eth.gas_price,
        "nonce": node.w3.eth.get_transaction_count(from_address),
        "chainId": node.w3.eth.chain_id,
    }

    # 2. Hash the transaction for signing
    # Note: web3.py's Transaction object handles the RLP encoding internally
    tx_object = node.w3.eth.account._prepare_transaction(tx_data)
    tx_hash_to_sign = tx_object.hash.hex()

    # 3. Orchestrate MPC signature
    mpc_signature = await node._orchestrate_signature_creation(
        dkg_public_key, tx_hash_to_sign, party
    )

    # 4. Assemble the final signed transaction
    # public_nonce may be an integer hex string or already a compressed SEC1 hex string
    try:
        if len(mpc_signature['public_nonce']) in (66, 130):  # compressed or uncompressed hex length
            public_nonce_point = SEC1Encoder.decode_public_key(bytes.fromhex(mpc_signature['public_nonce']), ecurve)
        else:
            public_nonce_point = code_to_pub(int(mpc_signature['public_nonce'], 16))
    except Exception:
        abort(500, "Invalid public nonce supplied")
    v = 27 + (public_nonce_point.y % 2)
    r = public_nonce_point.x
    s = mpc_signature['signature']

    encoded_tx = node.w3.eth.account._create_transaction_with_signature(tx_object, (v, r, s))

    # 5. Send the transaction to the blockchain
    sent_tx_hash = node.w3.eth.send_raw_transaction(encoded_tx.rawTransaction)

    return {"status": "SUCCESSFUL", "tx_hash": "0x" + sent_tx_hash.hex()}
