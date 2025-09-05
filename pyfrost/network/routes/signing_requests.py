from flask import Blueprint, request, jsonify, abort, current_app
from .decorators import async_request_handler
from pyfrost.network.models import SigningRequestStatus
from hashlib import sha256

signing_requests_bp = Blueprint('signing_requests', __name__)


@signing_requests_bp.route("/v1/signing-requests", methods=["POST"])
@async_request_handler
async def create_signing_request():
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
    node = current_app.node
    data = request.get_json()
    dkg_public_key = data["dkg_public_key"]
    message = data["message"]
    party = data["party"]
    request_id = data.get("request_id", sha256(message.encode()).hexdigest())

    if request_id in node.signing_requests:
        abort(409, f"Signing request with ID {request_id} already exists.")

    node.signing_requests[request_id] = {
        "dkg_public_key": dkg_public_key,
        "message": message,
        "party": party,
        "status": SigningRequestStatus.PENDING.value,
        "signature_data": None,
    }

    return {"request_id": request_id, "status": "PENDING"}


@signing_requests_bp.route(
    "/v1/signing-requests/<request_id>", methods=["GET"]
)
@async_request_handler
async def get_signing_request_details(request_id):
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
    node = current_app.node
    signing_request = node.signing_requests.get(request_id)
    if not signing_request:
        abort(404, "Signing request not found")
    return {"signing_request": signing_request}


@signing_requests_bp.route(
    "/v1/signing-requests/<request_id>/execute", methods=["POST"]
)
@async_request_handler
async def execute_signing_request(request_id):
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
    node = current_app.node
    signing_request = node.signing_requests.get(request_id)
    if not signing_request:
        abort(404, "Signing request not found")
    if signing_request["status"] != SigningRequestStatus.PENDING.value:
        abort(
            400,
            f"Signing request is not in PENDING state, but in {signing_request['status']}",
        )

    signature = await node._orchestrate_signature_creation(
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


@signing_requests_bp.route(
    "/v1/signing-requests/<request_id>/reject", methods=["POST"]
)
@async_request_handler
async def reject_signing_request(request_id):
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
    node = current_app.node
    signing_request = node.signing_requests.get(request_id)
    if not signing_request:
        abort(404, "Signing request not found")
    if signing_request["status"] != SigningRequestStatus.PENDING.value:
        abort(400, "Can only reject a PENDING signing request.")

    signing_request["status"] = SigningRequestStatus.REJECTED.value
    return {"request_id": request_id, "status": "REJECTED"}
