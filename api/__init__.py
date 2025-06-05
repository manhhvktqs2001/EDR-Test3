from flask import Blueprint
import logging

# Create main API blueprint
api = Blueprint('api', __name__, url_prefix='/api')

# Import and register sub-blueprints
try:
    from .agents import agents_api
    from .alerts import alerts_api
    from .rules import rules_api
    from .dashboard import dashboard_api
    
    # Register sub-blueprints
    api.register_blueprint(agents_api)
    api.register_blueprint(alerts_api)
    api.register_blueprint(rules_api)
    api.register_blueprint(dashboard_api)
    
    logging.info("API blueprints registered successfully")
    
except ImportError as e:
    logging.error(f"Error importing API blueprints: {e}")

# API version and info
API_VERSION = "2.0"
API_INFO = {
    "version": API_VERSION,
    "title": "EDR Backend API",
    "description": "Endpoint Detection and Response System API",
    "features": [
        "Dynamic field mapping",
        "Real-time rule processing", 
        "Cross-platform support",
        "Comprehensive logging",
        "RESTful endpoints",
        "WebSocket communication"
    ]
}