import time
import threading
import logging
import atexit
import sys
import json
from datetime import datetime
from queue import Queue
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, emit
from config import SERVER_SETTINGS, LOGGING_CONFIG, PERFORMANCE_SETTINGS
from database.connection import DatabaseConnection
from database.agents import AgentDB
from database.rules import RuleDB
from database.alerts import AlertDB
from database.logs import LogDB
from rules.rule_engine import RuleEngine

# Configure logging
logging.basicConfig(
    level=LOGGING_CONFIG['level'],
    format=LOGGING_CONFIG['format'],
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOGGING_CONFIG['file'], encoding='utf-8')
    ]
)

# Flask & SocketIO setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'edr_secret_key'
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    ping_timeout=PERFORMANCE_SETTINGS['ping_timeout'],
    ping_interval=PERFORMANCE_SETTINGS['socket_timeout'],
    reconnection=True,
    logger=False,
    engineio_logger=False
)

# Global components
connected_agents = {}  # {sid: {hostname, last_seen, agent_info}}
shutdown_event = threading.Event()
log_processing_queue = Queue(maxsize=1000)

# Initialize database components
try:
    db_connection = DatabaseConnection()
    agent_db = AgentDB()
    rule_db = RuleDB()
    alert_db = AlertDB()
    log_db = LogDB()
    rule_engine = RuleEngine()
    logging.info("Database components initialized successfully")
except Exception as e:
    logging.error(f"Failed to initialize database components: {e}")
    sys.exit(1)

def get_sid_by_hostname(hostname):
    """Get SocketIO session ID by hostname"""
    for sid, info in connected_agents.items():
        if info.get('hostname') == hostname:
            return sid
    return None

def get_hostname_by_sid(sid):
    """Get hostname by SocketIO session ID"""
    return connected_agents.get(sid, {}).get('hostname')

def validate_agent_data(data):
    """Validate agent registration data"""
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    required_fields = ['hostname', 'os_type']
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Missing required field: {field}"
    
    if data['hostname'] in ['Unknown', 'Windows', 'Linux']:
        return False, f"Invalid hostname: {data['hostname']}"
    
    return True, None

def process_log_with_rules(log_type, log_data, hostname):
    """Process log and check against rules"""
    try:
        # Store log in database
        success = log_db.process_log(log_type, log_data)
        if not success:
            logging.error(f"Failed to store {log_type} log from {hostname}")
            return False
        
        # Check rules
        violation = rule_engine.check_rules(log_type.upper() + '_LOGS', log_data, hostname)
        
        if violation:
            rule_violated, description, detection_data, severity, rule_id, action = violation
            
            if rule_violated:
                # Create alert
                alert_data = {
                    'hostname': hostname,
                    'rule_id': rule_id,
                    'alert_type': f'{log_type.title()} Violation',
                    'severity': severity,
                    'title': f'{log_type.title()} Rule Violation: {log_data.get("ProcessName") or log_data.get("FileName") or "Unknown"}',
                    'description': description,
                    'detection_data': detection_data,
                    'action': action
                }
                
                alert_success = alert_db.create_alert(alert_data)
                
                if alert_success:
                    # Send alert to agent
                    send_alert_to_agent(hostname, {
                        'type': f'{log_type}_violation',
                        'severity': severity,
                        'title': alert_data['title'],
                        'message': description,
                        'action': action,
                        'timestamp': datetime.now().isoformat(),
                        **_extract_alert_context(log_type, log_data)
                    })
                    
                    logging.info(f"Alert sent to agent {hostname} - {log_type} violation")
                    return True
        
        return True
        
    except Exception as e:
        logging.error(f"Error processing {log_type} log with rules: {e}")
        return False

def _extract_alert_context(log_type, log_data):
    """Extract context data for alerts based on log type"""
    context = {}
    
    if log_type == 'process':
        context.update({
            'process_name': log_data.get('ProcessName', ''),
            'process_id': log_data.get('ProcessID', 0),
            'command_line': log_data.get('CommandLine', ''),
            'executable_path': log_data.get('ExecutablePath', '')
        })
    elif log_type == 'file':
        context.update({
            'file_name': log_data.get('FileName', ''),
            'file_path': log_data.get('FilePath', ''),
            'event_type': log_data.get('EventType', ''),
            'file_size': log_data.get('FileSize', 0)
        })
    elif log_type == 'network':
        context.update({
            'process_name': log_data.get('ProcessName', ''),
            'remote_address': log_data.get('RemoteAddress', ''),
            'remote_port': log_data.get('RemotePort', ''),
            'protocol': log_data.get('Protocol', ''),
            'direction': log_data.get('Direction', '')
        })
    
    return context

def send_alert_to_agent(hostname, alert_data):
    """Send alert notification to specific agent"""
    try:
        agent_sid = get_sid_by_hostname(hostname)
        if agent_sid:
            socketio.emit('alert_notification', alert_data, room=agent_sid)
            logging.debug(f"Alert notification sent to agent {hostname} (SID: {agent_sid})")
        else:
            logging.warning(f"Agent {hostname} not connected, cannot send alert")
    except Exception as e:
        logging.error(f"Error sending alert to agent {hostname}: {e}")

# SocketIO Event Handlers
@socketio.on('connect')
def handle_connect():
    """Handle agent connection"""
    try:
        sid = request.sid
        connected_agents[sid] = {
            "hostname": None, 
            "last_seen": time.time(),
            "agent_info": {}
        }
        emit('connect_response', {'status': 'connected', 'sid': sid})
        logging.info(f"Agent connected - SID: {sid}")
        return True
    except Exception as e:
        logging.error(f"Connection failed: {e}")
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Handle agent disconnection"""
    try:
        sid = request.sid
        agent_info = connected_agents.pop(sid, None)
        if agent_info and agent_info.get('hostname'):
            agent_db.update_agent_status(agent_info['hostname'], 'Offline')
            logging.info(f"Agent disconnected: {agent_info['hostname']} (SID: {sid})")
        else:
            logging.info(f"Unknown agent disconnected - SID: {sid}")
    except Exception as e:
        logging.error(f"Disconnect handling failed: {e}")

@socketio.on('register')
def handle_register(data):
    """Handle agent registration"""
    try:
        sid = request.sid
        
        # Validate data
        is_valid, error_msg = validate_agent_data(data)
        if not is_valid:
            emit('error', {'message': error_msg})
            logging.error(f"Invalid registration data from SID {sid}: {error_msg}")
            return False
        
        hostname = data['hostname']
        
        # Register agent in database
        success = agent_db.register_agent(data)
        if not success:
            emit('error', {'message': 'Failed to register agent in database'})
            logging.error(f"Failed to register agent {hostname} in database")
            return False
        
        # Update connection info
        connected_agents[sid].update({
            "hostname": hostname,
            "last_seen": time.time(),
            "agent_info": data
        })
        
        # Send success response
        emit('register_response', {
            'status': 'success',
            'message': f'Agent {hostname} registered successfully',
            'hostname': hostname,
            'os_type': data.get('os_type'),
            'timestamp': datetime.now().isoformat()
        })
        
        logging.info(f"Agent registered successfully: {hostname} (SID: {sid})")
        return True
        
    except Exception as e:
        logging.error(f"Registration failed: {e}")
        emit('error', {'message': f'Registration error: {str(e)}'})
        return False

@socketio.on('heartbeat')
def handle_heartbeat(data):
    """Handle agent heartbeat"""
    try:
        sid = request.sid
        if sid in connected_agents:
            connected_agents[sid]['last_seen'] = time.time()
            hostname = connected_agents[sid].get('hostname')
            
            if hostname:
                agent_db.update_heartbeat(hostname)
                emit('heartbeat_response', {
                    "status": "alive", 
                    "timestamp": time.time(),
                    "server_time": datetime.now().isoformat()
                })
                logging.debug(f"Heartbeat received from {hostname}")
            else:
                emit('heartbeat_response', {"status": "alive", "timestamp": time.time()})
        else:
            emit('error', {'message': 'Agent not registered'})
            
    except Exception as e:
        logging.error(f"Heartbeat handling failed: {e}")

@socketio.on('process_logs')
def handle_process_logs(data):
    """Handle process logs from agent"""
    try:
        if not isinstance(data, dict) or 'hostname' not in data or 'logs' not in data:
            logging.error("Invalid process log data format")
            emit('error', {'message': 'Invalid log data format'})
            return
        
        hostname = data['hostname']
        logs = data['logs']
        
        if not isinstance(logs, list):
            logging.error("Process logs must be a list")
            emit('error', {'message': 'Logs must be a list'})
            return
        
        # Process each log
        processed_count = 0
        for log in logs:
            try:
                # Add hostname to log if missing
                if 'Hostname' not in log:
                    log['Hostname'] = hostname
                
                # Process log with rule checking
                if process_log_with_rules('process', log, hostname):
                    processed_count += 1
                    
            except Exception as e:
                logging.error(f"Error processing individual process log: {e}")
                continue
        
        logging.info(f"Processed {processed_count}/{len(logs)} process logs from {hostname}")
        emit('log_response', {
            'status': 'success',
            'processed': processed_count,
            'total': len(logs)
        })
        
    except Exception as e:
        logging.error(f"Error handling process logs: {e}")
        emit('error', {'message': 'Error processing process logs'})

@socketio.on('file_logs')
def handle_file_logs(data):
    """Handle file logs from agent"""
    try:
        if not isinstance(data, dict) or 'hostname' not in data or 'logs' not in data:
            logging.error("Invalid file log data format")
            emit('error', {'message': 'Invalid log data format'})
            return
        
        hostname = data['hostname']
        logs = data['logs']
        
        if not isinstance(logs, list):
            logging.error("File logs must be a list")
            emit('error', {'message': 'Logs must be a list'})
            return
        
        # Process each log
        processed_count = 0
        for log in logs:
            try:
                # Add hostname to log if missing
                if 'Hostname' not in log:
                    log['Hostname'] = hostname
                
                # Process log with rule checking
                if process_log_with_rules('file', log, hostname):
                    processed_count += 1
                    
            except Exception as e:
                logging.error(f"Error processing individual file log: {e}")
                continue
        
        logging.info(f"Processed {processed_count}/{len(logs)} file logs from {hostname}")
        emit('log_response', {
            'status': 'success',
            'processed': processed_count,
            'total': len(logs)
        })
        
    except Exception as e:
        logging.error(f"Error handling file logs: {e}")
        emit('error', {'message': 'Error processing file logs'})

@socketio.on('network_logs')
def handle_network_logs(data):
    """Handle network logs from agent"""
    try:
        if not isinstance(data, dict) or 'hostname' not in data or 'logs' not in data:
            logging.error("Invalid network log data format")
            emit('error', {'message': 'Invalid log data format'})
            return
        
        hostname = data['hostname']
        logs = data['logs']
        
        if not isinstance(logs, list):
            logging.error("Network logs must be a list")
            emit('error', {'message': 'Logs must be a list'})
            return
        
        # Process each log
        processed_count = 0
        for log in logs:
            try:
                # Add hostname to log if missing
                if 'Hostname' not in log:
                    log['Hostname'] = hostname
                
                # Process log with rule checking
                if process_log_with_rules('network', log, hostname):
                    processed_count += 1
                    
            except Exception as e:
                logging.error(f"Error processing individual network log: {e}")
                continue
        
        logging.info(f"Processed {processed_count}/{len(logs)} network logs from {hostname}")
        emit('log_response', {
            'status': 'success',
            'processed': processed_count,
            'total': len(logs)
        })
        
    except Exception as e:
        logging.error(f"Error handling network logs: {e}")
        emit('error', {'message': 'Error processing network logs'})

# REST API Endpoints
@app.route('/')
def index():
    """API root endpoint"""
    return jsonify({
        "message": "EDR Backend Server is running",
        "version": "2.0",
        "timestamp": datetime.now().isoformat(),
        "connected_agents": len(connected_agents)
    })

@app.route('/api/agents', methods=['GET'])
def api_get_agents():
    """Get all agents"""
    try:
        agents = agent_db.get_all_agents()
        return jsonify({
            'status': 'success',
            'data': agents,
            'count': len(agents)
        })
    except Exception as e:
        logging.error(f"Error getting agents: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/agents/<hostname>', methods=['GET'])
def api_get_agent(hostname):
    """Get specific agent details"""
    try:
        agent = agent_db.get_agent(hostname)
        if agent:
            return jsonify({
                'status': 'success',
                'data': agent
            })
        else:
            return jsonify({'error': 'Agent not found'}), 404
    except Exception as e:
        logging.error(f"Error getting agent {hostname}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def api_get_logs():
    """Get logs with filtering"""
    try:
        log_type = request.args.get('type')
        hostname = request.args.get('hostname')
        from_time = request.args.get('from')
        to_time = request.args.get('to')
        limit = int(request.args.get('limit', 100))
        
        if not log_type:
            return jsonify({'error': 'Log type is required'}), 400
        
        # Build filters
        filters = {}
        if hostname:
            filters['Hostname'] = hostname
        
        # Get logs based on type
        table_mapping = {
            'process': 'ProcessLogs',
            'file': 'FileLogs',
            'network': 'NetworkLogs'
        }
        
        table_name = table_mapping.get(log_type)
        if not table_name:
            return jsonify({'error': 'Invalid log type'}), 400
        
        logs = log_db.get_logs(table_name, filters, limit)
        
        return jsonify({
            'status': 'success',
            'data': logs,
            'count': len(logs),
            'type': log_type
        })
        
    except Exception as e:
        logging.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def api_get_alerts():
    """Get alerts with filtering"""
    try:
        filters = {}
        
        # Extract filter parameters
        for param in ['severity', 'status', 'hostname', 'alert_type']:
            value = request.args.get(param)
            if value:
                filters[param] = value
        
        # Handle date range
        from_date = request.args.get('from')
        to_date = request.args.get('to')
        if from_date:
            filters['from_date'] = from_date
        if to_date:
            filters['to_date'] = to_date
        
        limit = int(request.args.get('limit', 100))
        
        alerts = alert_db.get_alerts(filters, limit)
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts)
        })
        
    except Exception as e:
        logging.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts', methods=['POST'])
def api_create_alert():
    """Create new alert"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        success = alert_db.create_alert(data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Alert created successfully'
            }), 201
        else:
            return jsonify({'error': 'Failed to create alert'}), 500
            
    except Exception as e:
        logging.error(f"Error creating alert: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>', methods=['PUT'])
def api_update_alert(alert_id):
    """Update alert status"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        status = data.get('status')
        action = data.get('action')
        
        if not status:
            return jsonify({'error': 'Status is required'}), 400
        
        success = alert_db.update_alert_status(alert_id, status, action)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Alert updated successfully'
            })
        else:
            return jsonify({'error': 'Failed to update alert'}), 500
            
    except Exception as e:
        logging.error(f"Error updating alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules', methods=['GET'])
def api_get_rules():
    """Get rules with filtering"""
    try:
        filters = {}
        
        # Extract filter parameters
        for param in ['rule_type', 'severity', 'is_active', 'action']:
            value = request.args.get(param)
            if value is not None:
                if param == 'is_active':
                    filters[param] = value.lower() in ['true', '1', 'yes']
                else:
                    filters[param] = value
        
        rules = rule_db.get_rules_dashboard(filters)
        
        return jsonify({
            'status': 'success',
            'data': rules,
            'count': len(rules)
        })
        
    except Exception as e:
        logging.error(f"Error getting rules: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules', methods=['POST'])
def api_create_rule():
    """Create new rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Check if it's a cross-platform rule
        if data.get('rule_type') == 'cross_platform' or 'WindowsConditions' in data or 'LinuxConditions' in data:
            success = rule_db.create_cross_platform_rule(data)
        else:
            success = rule_db.create_rule(data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Rule created successfully'
            }), 201
        else:
            return jsonify({'error': 'Failed to create rule'}), 500
            
    except Exception as e:
        logging.error(f"Error creating rule: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/<int:rule_id>', methods=['PUT'])
def api_update_rule(rule_id):
    """Update existing rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        success = rule_db.update_rule(rule_id, data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Rule updated successfully'
            })
        else:
            return jsonify({'error': 'Failed to update rule'}), 500
            
    except Exception as e:
        logging.error(f"Error updating rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
def api_delete_rule(rule_id):
    """Delete rule"""
    try:
        success = rule_db.delete_rule(rule_id)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Rule deleted successfully'
            })
        else:
            return jsonify({'error': 'Failed to delete rule'}), 500
            
    except Exception as e:
        logging.error(f"Error deleting rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/summary', methods=['GET'])
def api_dashboard_summary():
    """Get dashboard summary statistics"""
    try:
        # Get agents summary
        agents = agent_db.get_all_agents()
        agents_summary = {
            'total': len(agents),
            'online': len([a for a in agents if a.get('Status') == 'Online']),
            'offline': len([a for a in agents if a.get('Status') == 'Offline'])
        }
        
        # Get alerts summary
        alert_filters = {
            'start_time': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        }
        alerts_stats = alert_db.get_alert_stats(alert_filters)
        
        # Get rules summary
        rules = rule_db.get_all_rules()
        rules_summary = {
            'total': len(rules),
            'active': len([r for r in rules if r.get('IsActive')]),
            'inactive': len([r for r in rules if not r.get('IsActive')])
        }
        
        return jsonify({
            'status': 'success',
            'data': {
                'agents': agents_summary,
                'alerts': alerts_stats,
                'rules': rules_summary,
                'timestamp': datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        logging.error(f"Error getting dashboard summary: {e}")
        return jsonify({'error': str(e)}), 500

# Background Tasks
def cleanup_offline_agents():
    """Background task to mark offline agents"""
    while not shutdown_event.is_set():
        try:
            offline_count = agent_db.cleanup_offline_agents()
            if offline_count > 0:
                logging.info(f"Marked {offline_count} agents as offline")
            
            # Also clean up disconnected socket sessions
            current_time = time.time()
            offline_sids = []
            
            for sid, info in connected_agents.items():
                if current_time - info.get('last_seen', 0) > 300:  # 5 minutes
                    offline_sids.append(sid)
            
            for sid in offline_sids:
                agent_info = connected_agents.pop(sid, None)
                if agent_info and agent_info.get('hostname'):
                    logging.info(f"Cleaned up stale connection for {agent_info['hostname']}")
            
        except Exception as e:
            logging.error(f"Error in cleanup task: {e}")
        
        # Wait 30 seconds before next cleanup
        for _ in range(30):
            if shutdown_event.is_set():
                break
            time.sleep(1)

def log_processing_worker():
    """Background worker to process logs from queue"""
    while not shutdown_event.is_set():
        try:
            # Process any queued logs
            if not log_processing_queue.empty():
                log_item = log_processing_queue.get(timeout=1)
                log_type, log_data, hostname = log_item
                process_log_with_rules(log_type, log_data, hostname)
                log_processing_queue.task_done()
            else:
                time.sleep(0.1)  # Short sleep when no work
                
        except Exception as e:
            logging.error(f"Error in log processing worker: {e}")
            time.sleep(1)

# Start background tasks
cleanup_thread = threading.Thread(target=cleanup_offline_agents, daemon=True)
cleanup_thread.start()

log_worker_thread = threading.Thread(target=log_processing_worker, daemon=True)
log_worker_thread.start()

logging.info("Background tasks started")

# Cleanup function
def cleanup():
    """Cleanup resources on shutdown"""
    try:
        shutdown_event.set()
        logging.info("Server shutting down...")
        
        # Close database connections
        if db_connection:
            db_connection.close()
        
        # Clear connected agents
        connected_agents.clear()
        
        logging.info("Cleanup completed")
        
    except Exception as e:
        logging.error(f"Error during cleanup: {e}")

atexit.register(cleanup)

# Import and register API blueprints
try:
    from api import api as api_blueprint
    app.register_blueprint(api_blueprint)
    logging.info("API blueprints registered")
except ImportError as e:
    logging.warning(f"Could not import API blueprints: {e}")

if __name__ == '__main__':
    try:
        logging.info("Starting EDR Backend Server...")
        logging.info(f"Server configuration: Host={SERVER_SETTINGS['host']}, Port={SERVER_SETTINGS['port']}")
        
        socketio.run(
            app, 
            host=SERVER_SETTINGS['host'], 
            port=SERVER_SETTINGS['port'], 
            debug=SERVER_SETTINGS.get('debug', False),
            use_reloader=False  # Disable reloader in production
        )
        
    except Exception as e:
        logging.error(f"Server startup failed: {e}")
        cleanup()
        sys.exit(1)