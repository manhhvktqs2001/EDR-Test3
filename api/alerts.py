from flask import Blueprint, request, jsonify
from database.alerts import AlertsDB
import logging

alerts_api = Blueprint('alerts_api', __name__)
db = AlertsDB()

@alerts_api.route('/api/alerts', methods=['GET'])
def get_alerts():
    # Lấy danh sách alert, có thể lọc theo hostname, severity, status
    hostname = request.args.get('hostname')
    severity = request.args.get('severity')
    status = request.args.get('status')
    alerts = db.get_alerts(severity=severity, status=status, hostname=hostname)
    return jsonify(alerts)

@alerts_api.route('/api/alerts', methods=['POST'])
def create_alert():
    data = request.json
    # Yêu cầu các trường bắt buộc
    required = ['hostname', 'rule_id', 'alert_type', 'severity', 'title', 'description']
    if not all(k in data for k in required):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        alerts_db = AlertsDB()
        alerts_db.insert_alert(
            hostname=data['hostname'],
            rule_id=data['rule_id'],
            alert_type=data['alert_type'],
            severity=data['severity'],
            status=data.get('status', 'New'),
            title=data['title'],
            description=data['description'],
            detection_data=data.get('detection_data', ''),
            action=data.get('action', '')
        )
        return jsonify({'status': 'success'})
    except Exception as e:
        logging.error(f"Error creating alert: {e}")
        return jsonify({'status': 'fail', 'error': str(e)}), 500

@alerts_api.route("/alerts/<int:alert_id>", methods=["PUT"])
def update_alert(alert_id):
    """Update alert status"""
    try:
        data = request.get_json()
        status = data.get("status")
        
        if not status:
            return jsonify({"error": "Status is required"}), 400
            
        alerts_db = AlertsDB()
        # TODO: Implement alert update logic
        return jsonify({"message": "Alert updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500 