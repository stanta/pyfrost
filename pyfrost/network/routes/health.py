from flask import Blueprint, jsonify, current_app

health_bp = Blueprint('health', __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
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
    node = current_app.node
    return jsonify({"status": "healthy", "node_id": node.node_id}), 200
