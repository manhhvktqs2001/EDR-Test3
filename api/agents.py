from flask import Blueprint, request, jsonify
from database.agents import AgentDB

agents_api = Blueprint('agents_api', __name__)

db = AgentDB()

@agents_api.route('/api/agent/register', methods=['POST'])
def register_agent():
    data = request.json
    if not data or 'Hostname' not in data or 'OSType' not in data:
        return jsonify({'error': 'Missing Hostname or OSType'}), 400
    success = db.register_agent(data)
    if success:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'fail'}), 500

@agents_api.route('/api/agents', methods=['GET'])
def get_agents():
    os_type = request.args.get('os_type')
    agents = db.get_agents(os_type)
    return jsonify([{
        'Hostname': a[0],
        'OSType': a[1],
        'OSVersion': a[2],
        'Architecture': a[3],
        'IPAddress': a[4],
        'Status': a[5],
        'LastSeen': a[6].isoformat() if a[6] else None
    } for a in agents])

@agents_api.route("/agents/<hostname>", methods=["GET"])
def get_agent_details(hostname):
    """Get agent details"""
    try:
        agent_db = AgentDB()
        agents = agent_db.get_agents()
        
        for agent in agents:
            if agent[0] == hostname:
                return jsonify({
                    "hostname": agent[0],
                    "os_type": agent[1],
                    "os_version": agent[2],
                    "architecture": agent[3],
                    "ip_address": agent[4],
                    "status": agent[5],
                    "last_seen": agent[6].strftime('%Y-%m-%d %H:%M:%S') if agent[6] else None
                }), 200
        return jsonify({"error": "Agent not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@agents_api.route("/agents/<hostname>/restart", methods=["POST"])
def restart_agent(hostname):
    """Restart an agent"""
    try:
        # TODO: Implement agent restart logic
        return jsonify({"message": "Restart command sent successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500 