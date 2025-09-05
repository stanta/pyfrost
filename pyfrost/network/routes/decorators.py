from functools import wraps
from flask import request, jsonify, abort, current_app
import logging
import json
from werkzeug.exceptions import HTTPException
from fastecdsa import ecdsa, curve


def async_request_handler(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        node = current_app.node
        route_path = request.url_rule.rule if request.url_rule else None
        if not node.caller_validator(request.remote_addr, route_path):
            abort(403)
        try:
            if request.method in ['POST', 'PUT'] and not request.is_json:
                logging.warning(f"Request from {request.remote_addr} to {route_path} has incorrect Content-Type: {request.content_type}")
            logging.debug(
                f"{request.remote_addr}{route_path} Got message: {request.get_json(silent=True)}"
            )
            result = await func(*args, **kwargs)
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
    def wrapper(*args, **kwargs):
        node = current_app.node
        route_path = request.url_rule.rule if request.url_rule else None
        if not node.caller_validator(request.remote_addr, route_path):
            abort(403)
        try:
            if request.method in ['POST', 'PUT'] and not request.is_json:
                logging.warning(f"Request from {request.remote_addr} to {route_path} has incorrect Content-Type: {request.content_type}")
            logging.debug(
                f"{request.remote_addr}{route_path} Got message: {request.get_json(silent=True)}"
            )
            result = func(*args, **kwargs)
            to_sign = json.dumps(result, sort_keys=True).encode("utf-8")
            result["node_signature"] = ecdsa.sign(
                to_sign, node.private, curve.secp256k1
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
