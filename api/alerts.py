from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
import json
from database.alerts import AlertDB
from database.agents import AgentDB

alerts_api = Blueprint('alerts_api', __name__, url_prefix='/alerts')
logger = logging.getLogger(__name__)

@alerts_api.route('', methods=['GET'])
def get_alerts():
    """Get alerts with dynamic filtering"""
    try:
        alert_db = AlertDB()
        
        # Extract filter parameters
        filters = {}
        
        # Basic filters
        severity = request.args.get('severity')
        status = request.args.get('status')
        hostname = request.args.get('hostname')
        alert_type = request.args.get('alert_type')
        rule_id = request.args.get('rule_id')
        
        # Date range filters
        from_date = request.args.get('from')
        to_date = request.args.get('to')
        hours = request.args.get('hours')  # Last N hours
        days = request.args.get('days')    # Last N days
        
        # Pagination
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        # Build filters dictionary
        if severity:
            filters['severity'] = severity
        if status:
            filters['status'] = status
        if hostname:
            filters['hostname'] = hostname
        if alert_type:
            filters['alert_type'] = alert_type
        if rule_id:
            filters['rule_id'] = int(rule_id)
        
        # Handle date range
        if hours:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=int(hours))
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
            filters['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        elif days:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=int(days))
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
            filters['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        elif from_date or to_date:
            if from_date:
                filters['start_time'] = from_date
            if to_date:
                filters['end_time'] = to_date
        
        # Get alerts
        alerts = alert_db.get_alerts(filters, limit)
        
        # Apply offset if specified
        if offset > 0:
            alerts = alerts[offset:]
        
        # Enhance alerts with additional information
        for alert in alerts:
            # Parse detection data if it's JSON string
            if alert.get('DetectionData'):
                try:
                    if isinstance(alert['DetectionData'], str):
                        alert['DetectionData'] = json.loads(alert['DetectionData'])
                except json.JSONDecodeError:
                    pass
            
            # Add time since alert
            if alert.get('Time'):
                try:
                    alert_time = datetime.strptime(alert['Time'], '%Y-%m-%d %H:%M:%S')
                    time_diff = datetime.now() - alert_time
                    alert['hours_ago'] = round(time_diff.total_seconds() / 3600, 1)
                    alert['is_recent'] = time_diff < timedelta(hours=1)
                except:
                    pass
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts),
            'filters_applied': filters,
            'pagination': {
                'limit': limit,
                'offset': offset
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('', methods=['POST'])
def create_alert():
    """Create a new alert"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        alert_db = AlertDB()
        success = alert_db.create_alert(data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Alert created successfully'
            }), 201
        else:
            return jsonify({'error': 'Failed to create alert'}), 500
            
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('/<int:alert_id>', methods=['GET'])
def get_alert_details(alert_id):
    """Get detailed information about a specific alert"""
    try:
        alert_db = AlertDB()
        alert = alert_db.get_alert_by_id(alert_id)
        
        if not alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Parse detection data if it's JSON string
        if alert.get('DetectionData'):
            try:
                if isinstance(alert['DetectionData'], str):
                    alert['DetectionData'] = json.loads(alert['DetectionData'])
            except json.JSONDecodeError:
                pass
        
        # Add time information
        if alert.get('Time'):
            try:
                alert_time = datetime.strptime(alert['Time'], '%Y-%m-%d %H:%M:%S')
                time_diff = datetime.now() - alert_time
                alert['hours_ago'] = round(time_diff.total_seconds() / 3600, 1)
                alert['is_recent'] = time_diff < timedelta(hours=1)
            except:
                pass
        
        return jsonify({
            'status': 'success',
            'data': alert
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('/<int:alert_id>', methods=['PUT'])
def update_alert(alert_id):
    """Update alert status and other fields"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        alert_db = AlertDB()
        
        # Check if alert exists
        existing_alert = alert_db.get_alert_by_id(alert_id)
        if not existing_alert:
            return jsonify({'error': 'Alert not found'}), 404
        
        # Extract update fields
        status = data.get('status')
        action = data.get('action')
        
        if not status:
            return jsonify({'error': 'status is required'}), 400
        
        # Validate status
        valid_statuses = ['New', 'In Progress', 'Resolved', 'False Positive']
        if status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {valid_statuses}'}), 400
        
        # Update alert
        success = alert_db.update_alert_status(alert_id, status, action)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Alert {alert_id} updated successfully'
            }), 200
        else:
            return jsonify({'error': 'Failed to update alert'}), 500
            
    except Exception as e:
        logger.error(f"Error updating alert {alert_id}: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('/stats', methods=['GET'])
def get_alert_statistics():
    """Get alert statistics and metrics"""
    try:
        alert_db = AlertDB()
        
        # Get time range from parameters
        hours = request.args.get('hours', 24)
        days = request.args.get('days')
        hostname = request.args.get('hostname')
        
        # Build filters for stats
        filters = {}
        
        if days:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=int(days))
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
            filters['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        else:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=int(hours))
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
            filters['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        
        if hostname:
            filters['hostname'] = hostname
        
        # Get statistics
        stats = alert_db.get_alert_stats(filters)
        
        # Get recent alerts for trend analysis
        recent_alerts = alert_db.get_alerts(filters, 1000)
        
        # Calculate trends
        trend_data = {}
        if recent_alerts:
            # Group by hour for trend analysis
            hourly_counts = {}
            for alert in recent_alerts:
                if alert.get('Time'):
                    try:
                        alert_time = datetime.strptime(alert['Time'], '%Y-%m-%d %H:%M:%S')
                        hour_key = alert_time.strftime('%Y-%m-%d %H:00')
                        hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
                    except:
                        continue
            
            trend_data = {
                'hourly_distribution': hourly_counts,
                'peak_hour': max(hourly_counts.items(), key=lambda x: x[1]) if hourly_counts else None,
                'total_in_period': len(recent_alerts)
            }
        
        return jsonify({
            'status': 'success',
            'data': {
                'summary': stats,
                'trends': trend_data,
                'time_range': {
                    'start_time': filters.get('start_time'),
                    'end_time': filters.get('end_time'),
                    'hostname': hostname
                }
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting alert statistics: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('/recent', methods=['GET'])
def get_recent_alerts():
    """Get recent alerts (last 24 hours by default)"""
    try:
        alert_db = AlertDB()
        
        # Get parameters
        hours = int(request.args.get('hours', 24))
        hostname = request.args.get('hostname')
        severity = request.args.get('severity')
        limit = int(request.args.get('limit', 50))
        
        # Get recent alerts
        alerts = alert_db.get_recent_alerts(hostname, hours, limit)
        
        # Filter by severity if specified
        if severity:
            alerts = [a for a in alerts if a.get('Severity', '').lower() == severity.lower()]
        
        # Enhance with time information
        for alert in alerts:
            if alert.get('Time'):
                try:
                    alert_time = datetime.strptime(alert['Time'], '%Y-%m-%d %H:%M:%S')
                    time_diff = datetime.now() - alert_time
                    alert['minutes_ago'] = int(time_diff.total_seconds() / 60)
                    alert['is_very_recent'] = time_diff < timedelta(minutes=30)
                except:
                    pass
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts),
            'filters': {
                'hours': hours,
                'hostname': hostname,
                'severity': severity,
                'limit': limit
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('/bulk-update', methods=['POST'])
def bulk_update_alerts():
    """Bulk update multiple alerts"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        alert_ids = data.get('alert_ids', [])
        new_status = data.get('status')
        action = data.get('action')
        
        if not alert_ids or not isinstance(alert_ids, list):
            return jsonify({'error': 'alert_ids must be a non-empty list'}), 400
        
        if not new_status:
            return jsonify({'error': 'status is required'}), 400
        
        # Validate status
        valid_statuses = ['New', 'In Progress', 'Resolved', 'False Positive']
        if new_status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {valid_statuses}'}), 400
        
        alert_db = AlertDB()
        results = {
            'success': [],
            'failed': [],
            'total': len(alert_ids)
        }
        
        for alert_id in alert_ids:
            try:
                success = alert_db.update_alert_status(alert_id, new_status, action)
                if success:
                    results['success'].append(alert_id)
                else:
                    results['failed'].append({'alert_id': alert_id, 'error': 'Update failed'})
            except Exception as e:
                results['failed'].append({'alert_id': alert_id, 'error': str(e)})
        
        return jsonify({
            'status': 'completed',
            'results': results,
            'summary': {
                'total': results['total'],
                'success_count': len(results['success']),
                'failed_count': len(results['failed'])
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error bulk updating alerts: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('/export', methods=['GET'])
def export_alerts():
    """Export alerts to various formats"""
    try:
        # Get format parameter
        export_format = request.args.get('format', 'json').lower()
        
        if export_format not in ['json', 'csv']:
            return jsonify({'error': 'Supported formats: json, csv'}), 400
        
        # Get filter parameters (reuse from get_alerts)
        alert_db = AlertDB()
        filters = {}
        
        # Apply same filtering logic as get_alerts
        for param in ['severity', 'status', 'hostname', 'alert_type']:
            value = request.args.get(param)
            if value:
                filters[param] = value
        
        # Date range
        hours = request.args.get('hours')
        if hours:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=int(hours))
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
            filters['end_time'] = end_time.strftime('%Y-%m-%d %H:%M:%S')
        
        # Get alerts
        limit = int(request.args.get('limit', 1000))
        alerts = alert_db.get_alerts(filters, limit)
        
        if export_format == 'json':
            return jsonify({
                'status': 'success',
                'export_format': 'json',
                'export_time': datetime.now().isoformat(),
                'filters': filters,
                'data': alerts,
                'count': len(alerts)
            }), 200
        
        elif export_format == 'csv':
            import csv
            import io
            
            # Create CSV content
            output = io.StringIO()
            if alerts:
                fieldnames = alerts[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for alert in alerts:
                    # Convert complex fields to strings
                    row = {}
                    for key, value in alert.items():
                        if isinstance(value, (dict, list)):
                            row[key] = json.dumps(value)
                        else:
                            row[key] = value
                    writer.writerow(row)
            
            csv_content = output.getvalue()
            output.close()
            
            # Return CSV as download
            from flask import Response
            return Response(
                csv_content,
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment; filename=alerts_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                }
            )
        
    except Exception as e:
        logger.error(f"Error exporting alerts: {e}")
        return jsonify({'error': str(e)}), 500

@alerts_api.route('/cleanup', methods=['POST'])
def cleanup_old_alerts():
    """Clean up old resolved alerts"""
    try:
        data = request.get_json() or {}
        days = data.get('days', 30)
        
        alert_db = AlertDB()
        deleted_count = alert_db.cleanup_old_alerts(days)
        
        return jsonify({
            'status': 'success',
            'message': f'Cleaned up {deleted_count} old alerts',
            'days_threshold': days,
            'deleted_count': deleted_count
        }), 200
        
    except Exception as e:
        logger.error(f"Error cleaning up old alerts: {e}")
        return jsonify({'error': str(e)}), 500