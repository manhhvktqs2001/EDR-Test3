from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
from database.agents import AgentDB
from database.rules import RuleDB

agents_api = Blueprint('agents_api', __name__, url_prefix='/agents')
logger = logging.getLogger(__name__)

@agents_api.route('', methods=['GET'])
def get_agents():
    """Get all agents with optional filtering"""
    try:
        agent_db = AgentDB()
        
        # Get query parameters for filtering
        os_type = request.args.get('os_type')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 100))
        
        # Get all agents
        agents = agent_db.get_all_agents()
        
        # Apply filters
        filtered_agents = agents
        
        if os_type:
            filtered_agents = [a for a in filtered_agents if a.get('OSType', '').lower() == os_type.lower()]
        
        if status:
            filtered_agents = [a for a in filtered_agents if a.get('Status', '').lower() == status.lower()]
        
        # Apply limit
        if limit > 0:
            filtered_agents = filtered_agents[:limit]
        
        # Add connection status and last seen info
        for agent in filtered_agents:
            if agent.get('LastSeen'):
                try:
                    last_seen = datetime.strptime(agent['LastSeen'], '%Y-%m-%d %H:%M:%S')
                    time_diff = datetime.now() - last_seen
                    agent['last_seen_minutes_ago'] = int(time_diff.total_seconds() / 60)
                    agent['is_online'] = time_diff < timedelta(minutes=5)
                except:
                    agent['last_seen_minutes_ago'] = None
                    agent['is_online'] = False
            else:
                agent['last_seen_minutes_ago'] = None
                agent['is_online'] = False
        
        return jsonify({
            'status': 'success',
            'data': filtered_agents,
            'count': len(filtered_agents),
            'total_count': len(agents),
            'filters_applied': {
                'os_type': os_type,
                'status': status,
                'limit': limit
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting agents: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/<hostname>', methods=['GET'])
def get_agent_details(hostname):
    """Get detailed information about a specific agent"""
    try:
        agent_db = AgentDB()
        agent = agent_db.get_agent(hostname)
        
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        # Add additional details
        if agent.get('LastSeen'):
            try:
                last_seen = datetime.strptime(agent['LastSeen'], '%Y-%m-%d %H:%M:%S')
                time_diff = datetime.now() - last_seen
                agent['last_seen_minutes_ago'] = int(time_diff.total_seconds() / 60)
                agent['is_online'] = time_diff < timedelta(minutes=5)
            except:
                agent['last_seen_minutes_ago'] = None
                agent['is_online'] = False
        
        # Get assigned rules count
        assigned_rules = agent_db.get_agent_rules(hostname)
        agent['assigned_rules_count'] = len(assigned_rules)
        
        return jsonify({
            'status': 'success',
            'data': agent
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting agent details for {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/<hostname>/rules', methods=['GET'])
def get_agent_rules(hostname):
    """Get rules assigned to a specific agent"""
    try:
        agent_db = AgentDB()
        rule_db = RuleDB()
        
        # Check if agent exists
        agent = agent_db.get_agent(hostname)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        # Get assigned rule IDs
        rule_ids = agent_db.get_agent_rules(hostname)
        
        # Get detailed rule information
        rules = []
        for rule_id in rule_ids:
            rule = rule_db.get_rule_by_id(rule_id)
            if rule:
                rules.append(rule)
        
        return jsonify({
            'status': 'success',
            'data': rules,
            'count': len(rules),
            'agent': hostname
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rules for agent {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/<hostname>/rules', methods=['POST'])
def assign_rule_to_agent(hostname):
    """Assign a rule to an agent"""
    try:
        agent_db = AgentDB()
        
        # Check if agent exists
        agent = agent_db.get_agent(hostname)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        data = request.get_json()
        if not data or 'rule_id' not in data:
            return jsonify({'error': 'rule_id is required'}), 400
        
        rule_id = data['rule_id']
        
        # Assign rule to agent
        success = agent_db.assign_rule(hostname, rule_id)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Rule {rule_id} assigned to agent {hostname}'
            }), 200
        else:
            return jsonify({'error': 'Failed to assign rule'}), 500
            
    except Exception as e:
        logger.error(f"Error assigning rule to agent {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/<hostname>/status', methods=['PUT'])
def update_agent_status(hostname):
    """Update agent status"""
    try:
        agent_db = AgentDB()
        
        # Check if agent exists
        agent = agent_db.get_agent(hostname)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'error': 'status is required'}), 400
        
        status = data['status']
        valid_statuses = ['Online', 'Offline', 'Maintenance']
        
        if status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {valid_statuses}'}), 400
        
        # Update agent status
        success = agent_db.update_agent_status(hostname, status)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Agent {hostname} status updated to {status}'
            }), 200
        else:
            return jsonify({'error': 'Failed to update agent status'}), 500
            
    except Exception as e:
        logger.error(f"Error updating status for agent {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/<hostname>/restart', methods=['POST'])
def restart_agent(hostname):
    """Send restart command to agent"""
    try:
        # This would typically send a command through SocketIO
        # For now, we'll just log the request
        logger.info(f"Restart command requested for agent {hostname}")
        
        # TODO: Implement actual restart command via SocketIO
        # Example: socketio.emit('restart_command', room=agent_sid)
        
        return jsonify({
            'status': 'success',
            'message': f'Restart command sent to agent {hostname}'
        }), 200
        
    except Exception as e:
        logger.error(f"Error sending restart command to agent {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/register', methods=['POST'])
def register_agent():
    """Register a new agent"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Validate required fields (dynamic field names supported)
        hostname = (data.get('hostname') or data.get('Hostname') or 
                   data.get('host') or data.get('computer_name'))
        os_type = (data.get('os_type') or data.get('OSType') or 
                  data.get('operating_system') or data.get('platform'))
        
        if not hostname:
            return jsonify({'error': 'hostname is required'}), 400
        if not os_type:
            return jsonify({'error': 'os_type is required'}), 400
        
        agent_db = AgentDB()
        success = agent_db.register_agent(data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Agent {hostname} registered successfully',
                'hostname': hostname
            }), 201
        else:
            return jsonify({'error': 'Failed to register agent'}), 500
            
    except Exception as e:
        logger.error(f"Error registering agent: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/summary', methods=['GET'])
def get_agents_summary():
    """Get summary statistics for all agents"""
    try:
        agent_db = AgentDB()
        agents = agent_db.get_all_agents()
        
        # Calculate statistics
        total_agents = len(agents)
        online_agents = 0
        offline_agents = 0
        by_os = {}
        by_status = {}
        
        for agent in agents:
            # Check if agent is actually online based on last seen
            if agent.get('LastSeen'):
                try:
                    last_seen = datetime.strptime(agent['LastSeen'], '%Y-%m-%d %H:%M:%S')
                    is_online = datetime.now() - last_seen < timedelta(minutes=5)
                    if is_online:
                        online_agents += 1
                    else:
                        offline_agents += 1
                except:
                    offline_agents += 1
            else:
                offline_agents += 1
            
            # Count by OS
            os_type = agent.get('OSType', 'Unknown')
            by_os[os_type] = by_os.get(os_type, 0) + 1
            
            # Count by status
            status = agent.get('Status', 'Unknown')
            by_status[status] = by_status.get(status, 0) + 1
        
        return jsonify({
            'status': 'success',
            'data': {
                'total_agents': total_agents,
                'online_agents': online_agents,
                'offline_agents': offline_agents,
                'by_operating_system': by_os,
                'by_status': by_status,
                'timestamp': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting agents summary: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/cleanup', methods=['POST'])
def cleanup_offline_agents():
    """Cleanup offline agents"""
    try:
        agent_db = AgentDB()
        
        # Get threshold from request or use default (5 minutes)
        data = request.get_json() or {}
        threshold_minutes = data.get('threshold_minutes', 5)
        
        count = agent_db.cleanup_offline_agents(threshold_minutes)
        
        return jsonify({
            'status': 'success',
            'message': f'Marked {count} agents as offline',
            'threshold_minutes': threshold_minutes,
            'agents_updated': count
        }), 200
        
    except Exception as e:
        logger.error(f"Error cleaning up offline agents: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/<hostname>/logs', methods=['GET'])
def get_agent_logs(hostname):
    """Get logs for a specific agent"""
    try:
        from database.logs import LogDB
        
        # Check if agent exists
        agent_db = AgentDB()
        agent = agent_db.get_agent(hostname)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        log_db = LogDB()
        
        # Get query parameters
        log_type = request.args.get('type', 'all')  # process, file, network, all
        limit = int(request.args.get('limit', 100))
        from_time = request.args.get('from')
        to_time = request.args.get('to')
        
        logs = {}
        
        if log_type in ['process', 'all']:
            logs['process'] = log_db.get_process_logs(hostname, from_time, to_time, limit)
        
        if log_type in ['file', 'all']:
            logs['file'] = log_db.get_file_logs(hostname, from_time, to_time, limit)
        
        if log_type in ['network', 'all']:
            logs['network'] = log_db.get_network_logs(hostname, from_time, to_time, limit)
        
        # Calculate total count
        total_count = sum(len(log_list) for log_list in logs.values())
        
        return jsonify({
            'status': 'success',
            'data': logs,
            'total_count': total_count,
            'agent': hostname,
            'filters': {
                'type': log_type,
                'limit': limit,
                'from': from_time,
                'to': to_time
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting logs for agent {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/<hostname>/alerts', methods=['GET'])
def get_agent_alerts(hostname):
    """Get alerts for a specific agent"""
    try:
        from database.alerts import AlertDB
        
        # Check if agent exists
        agent_db = AgentDB()
        agent = agent_db.get_agent(hostname)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        alert_db = AlertDB()
        
        # Get query parameters
        severity = request.args.get('severity')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 100))
        
        # Build filters
        filters = {'hostname': hostname}
        if severity:
            filters['severity'] = severity
        if status:
            filters['status'] = status
        
        alerts = alert_db.get_alerts(filters, limit)
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts),
            'agent': hostname,
            'filters': filters
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts for agent {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@agents_api.route('/bulk-actions', methods=['POST'])
def bulk_agent_actions():
    """Perform bulk actions on multiple agents"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        action = data.get('action')
        hostnames = data.get('hostnames', [])
        
        if not action:
            return jsonify({'error': 'action is required'}), 400
        if not hostnames or not isinstance(hostnames, list):
            return jsonify({'error': 'hostnames must be a non-empty list'}), 400
        
        agent_db = AgentDB()
        results = {
            'success': [],
            'failed': [],
            'action': action
        }
        
        for hostname in hostnames:
            try:
                if action == 'update_status':
                    status = data.get('status', 'Offline')
                    success = agent_db.update_agent_status(hostname, status)
                elif action == 'assign_rule':
                    rule_id = data.get('rule_id')
                    if not rule_id:
                        results['failed'].append({'hostname': hostname, 'error': 'rule_id required'})
                        continue
                    success = agent_db.assign_rule(hostname, rule_id)
                else:
                    results['failed'].append({'hostname': hostname, 'error': f'Unknown action: {action}'})
                    continue
                
                if success:
                    results['success'].append(hostname)
                else:
                    results['failed'].append({'hostname': hostname, 'error': 'Operation failed'})
                    
            except Exception as e:
                results['failed'].append({'hostname': hostname, 'error': str(e)})
        
        return jsonify({
            'status': 'completed',
            'results': results,
            'summary': {
                'total': len(hostnames),
                'success_count': len(results['success']),
                'failed_count': len(results['failed'])
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error performing bulk agent actions: {e}")
        return jsonify({'error': str(e)}), 500