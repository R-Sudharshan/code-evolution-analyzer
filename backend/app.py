import logging
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from backend import config
from backend.api.routes import api
from backend.storage.repos import db


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    logging.basicConfig(level=logging.INFO)
    app.register_blueprint(api)

    # Serve the production build of the React dashboard when present.
    # (HashRouter is used, so no server-side path fallback is required.)
    dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
    if dist.is_dir():
        @app.get("/")
        def spa_index():
            return send_from_directory(dist, "index.html")

        @app.get("/assets/<path:filename>")
        def spa_assets(filename: str):
            return send_from_directory(dist / "assets", filename)

    @app.errorhandler(404)
    def _404(_):
        return jsonify({"error": "not found", "path": request.path}), 404

    @app.errorhandler(405)
    def _405(_):
        return jsonify({"error": "method not allowed", "path": request.path}), 405

    @app.errorhandler(Exception)
    def _500(e):
        app.logger.exception("internal error")
        return jsonify({"error": "internal error", "detail": str(e)}), 500

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "version": "1.0.0", "whitelist": config.TOOL_WHITELIST})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8484, threaded=True)
