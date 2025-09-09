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
async def send_transaction(dkg_public_key):
    """
    Creates, signs, and sends a transaction using the specified MPC wallet.
    """
    node = current_app.node
    data = request.get_json()
    chain = data.get("chain", "ETH")

    if chain == "ETH":
        if not node.w3:
            abort(500, "Ethereum RPC URL not configured for this node.")
        to_address = data["to"]
        value_in_eth = data["value_in_eth"]
        party = data["party"]

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

        tx_object = node.w3.eth.account._prepare_transaction(tx_data)
        tx_hash_to_sign = tx_object.hash.hex()

        mpc_signature = await node._orchestrate_signature_creation(
            dkg_public_key, tx_hash_to_sign, party, key_type='ETH'
        )

        try:
            if len(mpc_signature['public_nonce']) in (66, 130):
                public_nonce_point = SEC1Encoder.decode_public_key(bytes.fromhex(mpc_signature['public_nonce']), ecurve)
            else:
                public_nonce_point = code_to_pub(int(mpc_signature['public_nonce'], 16))
        except Exception:
            abort(500, "Invalid public nonce supplied")
        v = 27 + (public_nonce_point.y % 2)
        r = public_nonce_point.x
        s = mpc_signature['signature']

        encoded_tx = node.w3.eth.account._create_transaction_with_signature(tx_object, (v, r, s))
        sent_tx_hash = node.w3.eth.send_raw_transaction(encoded_tx.rawTransaction)
        return {"status": "SUCCESSFUL", "tx_hash": "0x" + sent_tx_hash.hex()}

    elif chain == "TRON":
        if not node.tron:
            abort(500, "TRON RPC URL not configured for this node.")
        to_address = data["to"]
        value_in_sun = data["value_in_sun"]
        party = data["party"]

        from_address_point = code_to_pub(int(dkg_public_key, 16))
        from_address = pub_to_addr(from_address_point)

        tx_data = node.tron.trx.transfer(from_address, to_address, value_in_sun).build()
        tx_hash_to_sign = tx_data['txID']

        mpc_signature = await node._orchestrate_signature_creation(
            dkg_public_key, tx_hash_to_sign, party, key_type='TRON'
        )

        try:
            if len(mpc_signature['public_nonce']) in (66, 130):
                public_nonce_point = SEC1Encoder.decode_public_key(bytes.fromhex(mpc_signature['public_nonce']), ecurve)
            else:
                public_nonce_point = code_to_pub(int(mpc_signature['public_nonce'], 16))
        except Exception:
            abort(500, "Invalid public nonce supplied")

        v = public_nonce_point.y % 2
        r = public_nonce_point.x
        s = mpc_signature['signature']

        signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big') + v.to_bytes(1, 'big')
        tx_data['signature'] = [signature.hex()]
        
        result = node.tron.trx.broadcast(tx_data)
        return {"status": "SUCCESSFUL", "tx_hash": result['txid']}

    else:
        abort(400, f"Unsupported chain: {chain}")
