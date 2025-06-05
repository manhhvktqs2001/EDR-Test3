from flask import jsonify, request
from . import api
from database.agents import AgentDB
from database.alerts import AlertsDB
from database.logs import LogsDB
from datetime import datetime, timedelta

@api.route("/dashboard/summary", methods=["GET"])
def get_dashboard_summary():
    """Get dashboard summary data"""
    try:
        # Get time range
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)  # Last 7 days by default
        
        # Get data from databases
        agent_db = AgentDB()
        alerts_db = AlertsDB()
        logs_db = LogsDB()
        
        # Get agent statistics
        agents = agent_db.get_agents()
        total_agents = len(agents)
        active_agents = len([a for a in agents if a[5] == "active"])
        
        # Get alert statistics
        alerts = alerts_db.get_alerts_dashboard(
            start_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            end_time=end_time.strftime('%Y-%m-%d %H:%M:%S')
        )
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a[4] == "critical"])
        
        # Get log statistics
        process_logs = logs_db.get_process_logs_dashboard(
            start_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            end_time=end_time.strftime('%Y-%m-%d %H:%M:%S')
        )
        file_logs = logs_db.get_file_logs_dashboard(
            start_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            end_time=end_time.strftime('%Y-%m-%d %H:%M:%S')
        )
        network_logs = logs_db.get_network_logs_dashboard(
            start_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            end_time=end_time.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        return jsonify({
            "agents": {
                "total": total_agents,
                "active": active_agents,
                "inactive": total_agents - active_agents
            },
            "alerts": {
                "total": total_alerts,
                "critical": critical_alerts,
                "high": len([a for a in alerts if a[4] == "high"]),
                "medium": len([a for a in alerts if a[4] == "medium"]),
                "low": len([a for a in alerts if a[4] == "low"])
            },
            "logs": {
                "process": len(process_logs),
                "file": len(file_logs),
                "network": len(network_logs)
            }
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route("/dashboard/timeline", methods=["GET"])
def get_dashboard_timeline():
    """Get dashboard timeline data"""
    try:
        # Get time range
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)  # Last 7 days by default
        
        # Get alerts for timeline
        alerts_db = AlertsDB()
        alerts = alerts_db.get_alerts_dashboard(
            start_time=start_time.strftime('%Y-%m-%d %H:%M:%S'),
            end_time=end_time.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        # Format alerts for timeline
        timeline_data = []
        for alert in alerts:
            timeline_data.append({
                "time": alert[1].strftime('%Y-%m-%d %H:%M:%S') if alert[1] else None,
                "type": "alert",
                "severity": alert[4],
                "title": alert[6],
                "description": alert[7],
                "hostname": alert[2]
            })
            
        return jsonify(timeline_data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500 