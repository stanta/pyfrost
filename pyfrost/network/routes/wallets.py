from flask import Blueprint, request, jsonify, abort, current_app
from .decorators import async_request_handler
from pyfrost.network.models import SigningRequestStatus
from hashlib import sha256
import json
import aiohttp

wallets_bp = Blueprint('wallets', __name__)


@wallets_bp.route("/v1/wallets", methods=["POST"])
@async_request_handler
async def create_wallet():
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
    node = current_app.node
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
            node._make_request(session, node_id, "/v1/dkg/round1", round1_payload)
            for node_id in party
        ]
        round1_results = await asyncio.gather(*round1_tasks)

        broadcasted_data_r1 = {
            res["broadcast"]["sender_id"]: res for res in round1_results
        }

        # Round 2
        round2_payload = {"dkg_id": dkg_id, "broadcasted_data": broadcasted_data_r1}
        round2_tasks = [
            node._make_request(session, node_id, "/v1/dkg/round2", round2_payload)
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
                node._make_request(session, node_id, "/v1/dkg/round3", payload)
            )

        round3_results = await asyncio.gather(*round3_tasks)

    final_pub_key = round3_results[0]["data"]["dkg_public_key"]
    if final_pub_key not in node.created_wallets:
        node.created_wallets.append(final_pub_key)

    return {"dkg_public_key": final_pub_key, "status": "SUCCESSFUL"}


@wallets_bp.route("/v1/wallets", methods=["GET"])
@async_request_handler
async def list_wallets():
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
    node = current_app.node
    wallets_with_details = []
    for pub_key in node.created_wallets:
        details = {"dkg_public_key": pub_key}
        try:
            key_data = node.data_manager.get_key(pub_key)
            if key_data:
                details["has_local_share"] = True
                details["key_type"] = key_data.get("key_type")
            else:
                details["has_local_share"] = False
        except Exception:  # Assuming get_key might fail if key not found
            details["has_local_share"] = False
        wallets_with_details.append(details)

    return {"wallets": wallets_with_details, "status": "SUCCESSFUL"}


@wallets_bp.route("/v1/wallets/<dkg_public_key>", methods=["GET"])
@async_request_handler
async def get_wallet_info(dkg_public_key):
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
    node = current_app.node
    if dkg_public_key not in node.created_wallets:
        abort(404, "Wallet not found")

    details = {"dkg_public_key": dkg_public_key}
    try:
        key_data = node.data_manager.get_key(dkg_public_key)
        if key_data:
            details["has_local_share"] = True
            details["key_type"] = key_data.get("key_type")
        else:
            details["has_local_share"] = False
    except Exception:
        details["has_local_share"] = False

    return {"wallet_info": details, "status": "SUCCESSFUL"}
