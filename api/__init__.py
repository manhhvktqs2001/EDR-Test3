from flask import Blueprint

# Create API blueprint
api = Blueprint('api', __name__)

# Import routes
from . import agents, alerts, rules, dashboard 