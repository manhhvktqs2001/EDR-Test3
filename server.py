import time
import threading
import logging
import atexit
import sys
from queue import Queue
from flask import Flask, jsonify, request, Response, render_template_string
from flask_socketio import SocketIO, emit
from database.connection import DatabaseConnection
from database.agents import AgentDB
from database.rules import RuleDB
from database.alerts import AlertDB
from database.logs import LogDB
from rules.rule_engine import RuleEngine
from datetime import datetime
import json

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('server.log', encoding='utf-8')
    ]
)

# --- Flask & SocketIO ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading', 
                   ping_timeout=60, ping_interval=25, 
                   reconnection=True, reconnection_attempts=5,
                   reconnection_delay=1000, reconnection_delay_max=5000)

# --- Globals ---
connected_agents = {}  # {sid: {hostname, last_seen}}
shutdown_event = threading.Event()
rule_engine = RuleEngine()
log_db = LogDB()
agent_db = AgentDB()
rule_db = RuleDB()
alert_db = AlertDB()

def get_sid_by_hostname(hostname):
    for sid, info in connected_agents.items():
        if info['hostname'] == hostname:
            return sid
    return None

def validate_log_data(log_data, required_fields):
    """Validate log data has all required fields"""
    if not log_data:
        return False, "No log data received"
    
    missing_fields = [field for field in required_fields if field not in log_data]
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    return True, None

# --- Agent Management ---
@socketio.on('connect')
def handle_connect():
    try:
        sid = request.sid
        connected_agents[sid] = {"hostname": None, "last_seen": time.time()}
        emit('connect_response', {'status': 'connected', 'sid': sid})
        return True
    except Exception as e:
        logging.error(f"ERROR: Connection failed - {e}")
        return False

@socketio.on('disconnect')
def handle_disconnect():
    try:
        sid = request.sid
        info = connected_agents.pop(sid, None)
        if info and info['hostname']:
            agent_db.update_status(info['hostname'], 'Offline')
    except Exception as e:
        logging.error(f"ERROR: Disconnect failed - {e}")

@socketio.on('register')
def handle_register(data):
    try:
        sid = request.sid
        if sid not in connected_agents:
            emit('error', {'message': 'Connection not established'})
            return False

        hostname = data.get('hostname')
        os_type = data.get('os_type')
        
        if not hostname or hostname in ['Unknown']:
            emit('error', {'message': f'Invalid hostname: {hostname}'})
            return False
        
        if not os_type or os_type not in ['Windows', 'Linux']:
            emit('error', {'message': f'Invalid OS type: {os_type}'})
            return False

        # Chuẩn bị dữ liệu agent
        agent_data = {
            'Hostname': hostname,
            'OSType': os_type,
            'OSVersion': data.get('os_version'),
            'Architecture': data.get('architecture'),
            'IPAddress': data.get('ip') or data.get('ip_address'),
            'MACAddress': data.get('mac') or data.get('mac_address'),
            'AgentVersion': data.get('version') or data.get('agent_version'),
            'Status': 'Online',
            'LastSeen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        try:
            # Thử cập nhật agent nếu đã tồn tại
            agent_db.register_or_update(
                hostname=hostname,
                os_type=os_type,
                os_version=data.get('os_version'),
                arch=data.get('architecture'),
                ip=data.get('ip') or data.get('ip_address'),
                mac=data.get('mac') or data.get('mac_address'),
                agent_version=data.get('version') or data.get('agent_version')
            )
            logging.info(f"SUCCESS: Agent updated - {hostname}")
        except Exception as e:
            if "Violation of UNIQUE KEY constraint" in str(e):
                # Nếu lỗi là do duplicate key, thử insert mới
                try:
                    agent_db.register_agent(agent_data)
                    logging.info(f"SUCCESS: New agent registered - {hostname}")
                except Exception as insert_error:
                    logging.error(f"ERROR: Agent registration failed - {insert_error}")
                    emit('error', {'message': f'Error registering agent: {str(insert_error)}'})
                    return False
            else:
                logging.error(f"ERROR: Agent update failed - {e}")
                emit('error', {'message': f'Error updating agent: {str(e)}'})
                return False
        
        # Cập nhật thông tin kết nối
        connected_agents[sid].update({"hostname": hostname, "last_seen": time.time()})
        
        # Gửi response thành công
        emit('register_response', {
            'status': 'success',
            'message': f'Agent {hostname} registered/updated successfully',
            'hostname': hostname,
            'os_type': os_type
        })
        
        return True
        
    except Exception as e:
        logging.error(f"ERROR: Registration failed - {e}")
        emit('error', {'message': f'Error registering agent: {str(e)}'})
        return False

@socketio.on('heartbeat')
def handle_heartbeat(data):
    try:
        sid = request.sid
        if sid in connected_agents:
            connected_agents[sid]['last_seen'] = time.time()
            hostname = connected_agents[sid]['hostname']
            if hostname:
                agent_db.update_heartbeat(hostname)
                emit('heartbeat_response', {"status": "alive", "timestamp": time.time()})
    except Exception as e:
        logging.error(f"ERROR: Heartbeat failed - {e}")

# --- Log & Alert Handling ---
def get_rules(log_type):
    """Lấy rules từ cache hoặc database"""
    try:
        # Lấy rules từ database
        rules = rule_db.get_rules_by_type(log_type)
        if not rules:
            return []
            
        # Chuyển đổi rules thành định dạng cần thiết
        formatted_rules = []
        for rule in rules:
            formatted_rule = {
                'id': rule[0],
                'name': rule[1],
                'description': rule[2],
                'type': rule[3],
                'condition': rule[4],
                'field': rule[5],
                'value': rule[6],
                'severity': rule[7],
                'enabled': rule[8]
            }
            formatted_rules.append(formatted_rule)
            
        return formatted_rules
        
    except Exception as e:
        logging.error(f"Error getting rules: {e}")
        return []

def check_rules(log_data, log_type):
    """Kiểm tra log với các rules"""
    try:
        # Lấy rules từ database
        rules = get_rules(log_type)
        if not rules:
            return
            
        # Kiểm tra từng rule
        for rule in rules:
            if not rule.get('enabled', True):
                continue
                
            # Kiểm tra điều kiện
            if rule.get('condition') == 'contains':
                if rule.get('value') in str(log_data.get(rule.get('field', ''), '')):
                    create_alert(log_data, rule)
            elif rule.get('condition') == 'equals':
                if rule.get('value') == log_data.get(rule.get('field', '')):
                    create_alert(log_data, rule)
            elif rule.get('condition') == 'regex':
                import re
                if re.search(rule.get('value', ''), str(log_data.get(rule.get('field', ''), ''))):
                    create_alert(log_data, rule)
                    
    except Exception as e:
        logging.error(f"Error checking rules: {e}")

def create_alert(log_data, rule):
    """Tạo alert từ rule match"""
    try:
        alert_data = {
            'timestamp': datetime.now().isoformat(),
            'hostname': log_data.get('Hostname', 'Unknown'),
            'rule_id': rule.get('id'),
            'rule_name': rule.get('name'),
            'rule_description': rule.get('description'),
            'severity': rule.get('severity', 'medium'),
            'log_data': log_data
        }
        
        # Lưu alert vào database
        try:
            alert_db.create_alert(
                timestamp=alert_data['timestamp'],
                hostname=alert_data['hostname'],
                rule_id=alert_data['rule_id'],
                rule_name=alert_data['rule_name'],
                rule_description=alert_data['rule_description'],
                severity=alert_data['severity'],
                log_data=json.dumps(alert_data['log_data'])
            )
            
            # Emit alert qua Socket.IO
            socketio.emit('new_alert', alert_data)
            
            logging.info(f"Created alert for rule {rule.get('name')} on {alert_data['hostname']}")
            
        except Exception as db_error:
            logging.error(f"Error creating alert in database: {db_error}")
            
    except Exception as e:
        logging.error(f"Error creating alert: {e}")

@socketio.on('send_log')
def handle_log(data):
    """Xử lý logs từ agent"""
    try:
        # Validate log data
        if not data or 'type' not in data or 'data' not in data:
            logging.error("Invalid log data format")
            return False
            
        log_type = data['type']
        log_data = data['data']
        
        # Validate required fields
        required_fields = ['hostname', 'logs']
        is_valid, error_msg = validate_log_data(log_data, required_fields)
        if not is_valid:
            logging.error(f"Invalid log data: {error_msg}")
            return False
            
        # Lưu log vào database
        try:
            if log_type == 'process':
                log_db.save_process_log(
                    hostname=log_data['hostname'],
                    logs=json.dumps(log_data['logs'])
                )
            elif log_type == 'network':
                log_db.save_network_log(
                    hostname=log_data['hostname'],
                    logs=json.dumps(log_data['logs'])
                )
            elif log_type == 'file':
                log_db.save_file_log(
                    hostname=log_data['hostname'],
                    logs=json.dumps(log_data['logs'])
                )
            else:
                logging.error(f"Unknown log type: {log_type}")
                return False
                
            # Kiểm tra rules
            check_rules(log_data, log_type)
            
            logging.info(f"Log saved: {log_type} from {log_data['hostname']}")
            return True
            
        except Exception as e:
            logging.error(f"Error saving log: {e}")
            return False
            
    except Exception as e:
        logging.error(f"Error handling log: {e}")
        return False

@socketio.on('process_logs')
def handle_process_logs(data):
    """Xử lý process logs từ agent"""
    try:
        # Validate data format
        if not isinstance(data, dict) or 'hostname' not in data or 'logs' not in data:
            logging.error("Invalid process log data format")
            return
            
        hostname = data['hostname']
        logs = data['logs']
        
        if not isinstance(logs, list):
            logging.error("Logs must be a list")
            return
            
        # Lưu từng log vào database
        for log in logs:
            try:
                # Validate required fields
                required_fields = ['ProcessID', 'ProcessName', 'CommandLine', 'ExecutablePath']
                valid, error = validate_log_data(log, required_fields)
                if not valid:
                    logging.error(f"Invalid process log: {error}")
                    continue
                    
                # Lưu log
                log_db.save_process_log(
                    hostname=hostname,
                    process_id=log.get('ProcessID'),
                    parent_process_id=log.get('ParentProcessID'),
                    process_name=log.get('ProcessName'),
                    command_line=log.get('CommandLine'),
                    executable_path=log.get('ExecutablePath'),
                    username=log.get('UserName'),
                    cpu_usage=log.get('CPUUsage'),
                    memory_usage=log.get('MemoryUsage'),
                    hash=log.get('Hash')
                )
                
                # Kiểm tra rules
                check_rules(log, 'process')
                
            except Exception as e:
                logging.error(f"Error saving process log: {e}")
                continue
                
    except Exception as e:
        logging.error(f"Error handling process logs: {e}")

@socketio.on('file_logs')
def handle_file_logs(data):
    """Xử lý file logs từ agent"""
    try:
        # Validate data format
        if not isinstance(data, dict) or 'hostname' not in data or 'logs' not in data:
            logging.error("Invalid file log data format")
            return
            
        hostname = data['hostname']
        logs = data['logs']
        
        if not isinstance(logs, list):
            logging.error("Logs must be a list")
            return
            
        # Lưu từng log vào database
        for log in logs:
            try:
                # Validate required fields
                required_fields = ['FileName', 'FilePath', 'ProcessID', 'ProcessName']
                valid, error = validate_log_data(log, required_fields)
                if not valid:
                    logging.error(f"Invalid file log: {error}")
                    continue
                    
                # Lưu log
                log_db.save_file_log(
                    hostname=hostname,
                    file_name=log.get('FileName'),
                    file_path=log.get('FilePath'),
                    file_size=log.get('FileSize'),
                    file_hash=log.get('FileHash'),
                    event_type=log.get('EventType'),
                    process_id=log.get('ProcessID'),
                    process_name=log.get('ProcessName')
                )
                
                # Kiểm tra rules
                check_rules(log, 'file')
                
            except Exception as e:
                logging.error(f"Error saving file log: {e}")
                continue
                
    except Exception as e:
        logging.error(f"Error handling file logs: {e}")

@socketio.on('network_logs')
def handle_network_logs(data):
    """Xử lý network logs từ agent"""
    try:
        # Validate data format
        if not isinstance(data, dict) or 'hostname' not in data or 'logs' not in data:
            logging.error("Invalid network log data format")
            return
            
        hostname = data['hostname']
        logs = data['logs']
        
        if not isinstance(logs, list):
            logging.error("Logs must be a list")
            return
            
        # Lưu từng log vào database
        for log in logs:
            try:
                # Validate required fields
                required_fields = ['ProcessID', 'ProcessName', 'LocalAddress', 'RemoteAddress']
                valid, error = validate_log_data(log, required_fields)
                if not valid:
                    logging.error(f"Invalid network log: {error}")
                    continue
                    
                # Parse addresses
                local_addr, local_port = log.get('LocalAddress', ':').split(':')
                remote_addr, remote_port = log.get('RemoteAddress', ':').split(':')
                
                # Lưu log
                log_db.save_network_log(
                    hostname=hostname,
                    process_id=log.get('ProcessID'),
                    process_name=log.get('ProcessName'),
                    protocol=log.get('Protocol'),
                    local_address=local_addr,
                    local_port=int(local_port) if local_port.isdigit() else 0,
                    remote_address=remote_addr,
                    remote_port=int(remote_port) if remote_port.isdigit() else 0,
                    direction=log.get('Direction')
                )
                
                # Kiểm tra rules
                check_rules(log, 'network')
                
            except Exception as e:
                logging.error(f"Error saving network log: {e}")
                continue
                
    except Exception as e:
        logging.error(f"Error handling network logs: {e}")

# --- Flask API ---
@app.route('/')
def index():
    return jsonify({"message": "EDR Backend Server is running"})

@app.route('/api/agents', methods=['GET'])
def api_agents():
    agents = AgentDB().get_all_agents()
    return jsonify(agents)

@app.route('/api/agents/<hostname>', methods=['GET'])
def api_agent_detail(hostname):
    agent = AgentDB().get_agent(hostname)
    if agent:
        return jsonify(agent)
    return jsonify({"error": "Agent not found"}), 404

@app.route('/api/logs', methods=['GET'])
def api_logs():
    log_type = request.args.get('type')
    hostname = request.args.get('hostname')
    from_time = request.args.get('from')
    to_time = request.args.get('to')
    limit = int(request.args.get('limit', 100))

    logdb = LogDB()
    logs = []
    
    try:
        if log_type == 'process':
            logs = logdb.get_process_logs(hostname, from_time, to_time, limit)
        elif log_type == 'network':
            logs = logdb.get_network_logs(hostname, from_time, to_time, limit)
        elif log_type == 'file':
            logs = logdb.get_file_logs(hostname, from_time, to_time, limit)
        else:
            return jsonify({"error": "Invalid log type"}), 400
            
        return jsonify(logs)
    except Exception as e:
        logging.error(f"ERROR: Get logs failed - {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    alerts = AlertDB().get_alerts(
        severity=request.args.get('severity'),
        status=request.args.get('status'),
        from_date=request.args.get('from'),
        to_date=request.args.get('to')
    )
    return jsonify(alerts)

@app.route('/api/rules', methods=['GET'])
def api_rules():
    rules = RuleDB().get_all_rules()
    return jsonify(rules)

@app.route('/api/rules', methods=['POST'])
def api_create_rule():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing rule data"}), 400
    RuleDB().create_rule(data)
    logging.info(f"SUCCESS: Rule created - {data.get('RuleName', 'Unknown')}")
    return jsonify({"message": "Rule created"}), 201

@app.route('/api/rules/<int:rule_id>', methods=['PUT'])
def api_update_rule(rule_id):
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing rule data"}), 400
    RuleDB().update_rule(rule_id, data)
    logging.info(f"SUCCESS: Rule updated - ID: {rule_id}")
    return jsonify({"message": "Rule updated"})

@app.route('/api/rules/<int:rule_id>', methods=['DELETE'])
def api_delete_rule(rule_id):
    RuleDB().delete_rule(rule_id)
    logging.info(f"SUCCESS: Rule deleted - ID: {rule_id}")
    return jsonify({"message": "Rule deleted"})

# --- Background job: Auto set Offline if agent lost heartbeat ---
def offline_checker():
    CHECK_INTERVAL = 30  # giây
    OFFLINE_TIMEOUT = 65  # giây (lớn hơn ping_timeout)
    while not shutdown_event.is_set():
        try:
            now = time.time()
            for sid, info in list(connected_agents.items()):
                last_seen = info.get('last_seen', 0)
                hostname = info.get('hostname')
                if hostname and (now - last_seen > OFFLINE_TIMEOUT):
                    agent_db.update_status(hostname, 'Offline')
                    logging.info(f"SUCCESS: Agent marked offline - {hostname}")
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            logging.error(f"ERROR: Offline checker failed - {e}")
            time.sleep(CHECK_INTERVAL)

# Khởi động background job khi start server
threading.Thread(target=offline_checker, daemon=True).start()

# --- Cleanup ---
def cleanup():
    shutdown_event.set()
    logging.info("Server shutting down...")

atexit.register(cleanup)

# --- Alert Handling ---
@socketio.on('alert_ack')
def on_alert_ack(data):
    try:
        required_fields = ['hostname', 'rule_id', 'alert_type', 'severity', 'title', 'description']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            logging.error(f"ERROR: Missing fields in alert_ack - {missing_fields}")
            return
            
        AlertDB().insert_alert(
            hostname=data.get('hostname'),
            rule_id=data.get('rule_id'),
            alert_type=data.get('alert_type'),
            severity=data.get('severity', 'Medium'),
            status='New',
            title=data.get('title', 'EDR Alert'),
            description=data.get('description', ''),
            detection_data=data.get('detection_data', ''),
            action=data.get('action', '')
        )
        logging.info(f"SUCCESS: Alert inserted - {data.get('hostname')} - RuleID: {data.get('rule_id')}")
    except Exception as e:
        logging.error(f"ERROR: Alert insertion failed - {e}")

@app.route('/api/heartbeat', methods=['POST'])
def heartbeat():
    try:
        data = request.get_json()
        hostname = data.get('Hostname')
        os_type = data.get('OSType')
        
        if not hostname or not os_type:
            return jsonify({'error': 'Missing required fields'}), 400

        agent_db = AgentDB()
        agent_db.update_agent_status(hostname, True)
        
        current_rules = agent_db.get_agent_rules(hostname)
        rule_db = RuleDB()
        rules = rule_db.get_rules()
        new_rules_assigned = 0

        for rule in rules:
            rule_ostype = rule.get('OSType', 'All')
            if rule_ostype == os_type or rule_ostype == 'All':
                if rule['RuleID'] not in current_rules:
                    try:
                        agent_db.assign_rule(hostname, rule['RuleID'])
                        new_rules_assigned += 1
                    except Exception as e:
                        logging.error(f"ERROR: Rule assignment failed - {e}")

        return jsonify({
            'status': 'success',
            'message': f'Heartbeat received. {new_rules_assigned} new rules assigned.' if new_rules_assigned > 0 else 'Heartbeat received.'
        })

    except Exception as e:
        logging.error(f"ERROR: Heartbeat failed - {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/disconnect', methods=['POST'])
def disconnect():
    try:
        data = request.get_json()
        hostname = data.get('Hostname')
        
        if not hostname:
            return jsonify({'error': 'Missing Hostname'}), 400

        agent_db = AgentDB()
        agent_db.update_agent_status(hostname, False)
        logging.info(f"SUCCESS: Agent disconnected - {hostname}")
        
        return jsonify({
            'status': 'success',
            'message': 'Agent disconnected successfully'
        })

    except Exception as e:
        logging.error(f"ERROR: Disconnect failed - {e}")
        return jsonify({'error': str(e)}), 500

@socketio.on('get_agent_status')
def on_get_agent_status(sid, data):
    try:
        hostname = data.get('hostname')
        if not hostname:
            socketio.emit('log_response', {'status': 'error', 'message': 'Hostname is required'})
            return
            
        agent_db = AgentDB()
        status = agent_db.get_agent_status(hostname)
        if status is None:
            socketio.emit('log_response', {'status': 'error', 'message': f'Agent {hostname} not found'})
            return
            
        socketio.emit('log_response', {'status': 'success', 'data': {'is_online': status == 'Online'}})
    except Exception as e:
        logging.error(f"ERROR: Get agent status failed - {e}")
        socketio.emit('log_response', {'status': 'error', 'message': 'Internal server error'})

if __name__ == '__main__':
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logging.error(f"ERROR: Server failed - {e}")
        cleanup()
        sys.exit(1)
