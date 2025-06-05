from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
import json
from database.rules import RuleDB
from database.agents import AgentDB
from database.alerts import AlertDB

rules_api = Blueprint('rules_api', __name__, url_prefix='/rules')
logger = logging.getLogger(__name__)

@rules_api.route('', methods=['GET'])
def get_rules():
    """Get rules with dynamic filtering and agent-specific rules"""
    try:
        rule_db = RuleDB()
        
        # Get query parameters for filtering
        rule_type = request.args.get('rule_type')
        severity = request.args.get('severity') 
        is_active = request.args.get('is_active')
        action = request.args.get('action')
        os_type = request.args.get('os_type')
        hostname = request.args.get('hostname')
        is_global = request.args.get('is_global')
        limit = int(request.args.get('limit', 100))
        
        # Build filters
        filters = {}
        if rule_type:
            filters['rule_type'] = rule_type
        if severity:
            filters['severity'] = severity
        if is_active is not None:
            filters['is_active'] = is_active.lower() in ['true', '1', 'yes']
        if action:
            filters['action'] = action
        if os_type:
            filters['os_type'] = os_type
        if is_global is not None:
            filters['is_global'] = is_global.lower() in ['true', '1', 'yes']
        
        # Get rules with statistics
        if hostname:
            # Get rules for specific agent
            agent_db = AgentDB()
            agent = agent_db.get_agent(hostname)
            if not agent:
                return jsonify({'error': 'Agent not found'}), 404
            
            agent_os = agent.get('OSType', 'All')
            rules = rule_db.get_agent_applicable_rules(hostname, agent_os)
        else:
            # Get all rules with dashboard statistics
            rules = rule_db.get_rules_dashboard(filters)
        
        # Apply limit
        if limit > 0:
            rules = rules[:limit]
        
        # Add usage statistics for each rule
        for rule in rules:
            rule_id = rule.get('RuleID')
            if rule_id:
                # Get alert count for this rule (last 30 days)
                alert_db = AlertDB()
                alert_filters = {
                    'rule_id': rule_id,
                    'start_time': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
                }
                recent_alerts = alert_db.get_alerts(alert_filters, 1000)
                rule['recent_alerts_count'] = len(recent_alerts)
                
                # Add severity distribution of alerts
                severity_dist = {}
                for alert in recent_alerts:
                    sev = alert.get('Severity', 'Unknown')
                    severity_dist[sev] = severity_dist.get(sev, 0) + 1
                rule['alert_severity_distribution'] = severity_dist
        
        return jsonify({
            'status': 'success',
            'data': rules,
            'count': len(rules),
            'filters_applied': filters,
            'agent_specific': hostname is not None
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('', methods=['POST'])
def create_rule():
    """Create new rule with dynamic field mapping"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        rule_db = RuleDB()
        
        # Check if it's a cross-platform rule
        if (data.get('rule_type') == 'cross_platform' or 
            'WindowsConditions' in data or 'LinuxConditions' in data or
            'windows_conditions' in data or 'linux_conditions' in data):
            
            success = rule_db.create_cross_platform_rule(data)
            rule_type = 'cross-platform'
        else:
            success = rule_db.create_rule(data)
            rule_type = 'standard'
        
        if success:
            rule_name = (data.get('RuleName') or data.get('rule_name') or 
                        data.get('name') or 'Unknown Rule')
            
            return jsonify({
                'status': 'success',
                'message': f'{rule_type.title()} rule "{rule_name}" created successfully',
                'rule_name': rule_name,
                'rule_type': rule_type
            }), 201
        else:
            return jsonify({'error': 'Failed to create rule'}), 500
            
    except Exception as e:
        logger.error(f"Error creating rule: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/<int:rule_id>', methods=['GET'])
def get_rule_details(rule_id):
    """Get detailed information about a specific rule"""
    try:
        rule_db = RuleDB()
        rule = rule_db.get_rule_by_id(rule_id)
        
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Get rule conditions
        rule_type = rule.get('RuleType', '')
        conditions = []
        
        try:
            if rule_type == 'Process':
                conditions = rule_db._load_process_conditions(rule_id)
            elif rule_type == 'File':
                conditions = rule_db._load_file_conditions(rule_id)
            elif rule_type == 'Network':
                conditions = rule_db._load_network_conditions(rule_id)
        except Exception as e:
            logger.warning(f"Could not load conditions for rule {rule_id}: {e}")
        
        rule['conditions'] = conditions
        
        # Get usage statistics
        alert_db = AlertDB()
        agent_db = AgentDB()
        
        # Total alerts generated by this rule
        alert_filters = {'rule_id': rule_id}
        total_alerts = alert_db.get_alerts(alert_filters, 10000)
        rule['total_alerts'] = len(total_alerts)
        
        # Recent alerts (last 7 days)
        recent_filters = {
            'rule_id': rule_id,
            'start_time': (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        }
        recent_alerts = alert_db.get_alerts(recent_filters, 1000)
        rule['recent_alerts'] = len(recent_alerts)
        
        # Agents with this rule assigned
        try:
            agents_query = """
                SELECT COUNT(DISTINCT ar.Hostname) as AgentCount
                FROM AgentRules ar
                WHERE ar.RuleID = ? AND ar.IsActive = 1
            """
            from database.connection import DatabaseConnection
            db = DatabaseConnection()
            db.connect()
            cursor = db.execute_query(agents_query, [rule_id])
            
            if cursor:
                row = cursor.fetchone()
                rule['assigned_agents_count'] = row.AgentCount if row else 0
            else:
                rule['assigned_agents_count'] = 0
                
        except Exception as e:
            logger.warning(f"Could not get agent count for rule {rule_id}: {e}")
            rule['assigned_agents_count'] = 0
        
        # Alert trend (last 30 days by day)
        trend_data = {}
        for alert in recent_alerts:
            if alert.get('Time'):
                try:
                    alert_date = datetime.strptime(alert['Time'], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
                    trend_data[alert_date] = trend_data.get(alert_date, 0) + 1
                except:
                    continue
        
        rule['alert_trend'] = trend_data
        
        return jsonify({
            'status': 'success',
            'data': rule
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rule details for {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/<int:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    """Update existing rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        rule_db = RuleDB()
        
        # Check if rule exists
        existing_rule = rule_db.get_rule_by_id(rule_id)
        if not existing_rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Update rule
        success = rule_db.update_rule(rule_id, data)
        
        if success:
            updated_rule = rule_db.get_rule_by_id(rule_id)
            rule_name = updated_rule.get('RuleName', f'Rule {rule_id}')
            
            return jsonify({
                'status': 'success',
                'message': f'Rule "{rule_name}" updated successfully',
                'rule_id': rule_id,
                'rule_name': rule_name
            }), 200
        else:
            return jsonify({'error': 'Failed to update rule'}), 500
            
    except Exception as e:
        logger.error(f"Error updating rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    """Delete or deactivate rule"""
    try:
        rule_db = RuleDB()
        
        # Check if rule exists
        existing_rule = rule_db.get_rule_by_id(rule_id)
        if not existing_rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        rule_name = existing_rule.get('RuleName', f'Rule {rule_id}')
        
        # Check for references before deletion
        references = rule_db._check_rule_references(rule_id)
        
        success = rule_db.delete_rule(rule_id)
        
        if success:
            if references > 0:
                message = f'Rule "{rule_name}" deactivated (had {references} references)'
                action = 'deactivated'
            else:
                message = f'Rule "{rule_name}" deleted successfully'
                action = 'deleted'
            
            return jsonify({
                'status': 'success',
                'message': message,
                'action': action,
                'rule_id': rule_id,
                'rule_name': rule_name,
                'references_count': references
            }), 200
        else:
            return jsonify({'error': 'Failed to delete rule'}), 500
            
    except Exception as e:
        logger.error(f"Error deleting rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/<int:rule_id>/toggle', methods=['POST'])
def toggle_rule_status(rule_id):
    """Toggle rule active/inactive status"""
    try:
        rule_db = RuleDB()
        
        # Get current rule
        rule = rule_db.get_rule_by_id(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Toggle status
        current_status = rule.get('IsActive', False)
        new_status = not current_status
        
        # Update rule
        update_data = {'IsActive': new_status}
        success = rule_db.update_rule(rule_id, update_data)
        
        if success:
            rule_name = rule.get('RuleName', f'Rule {rule_id}')
            status_text = 'activated' if new_status else 'deactivated'
            
            return jsonify({
                'status': 'success',
                'message': f'Rule "{rule_name}" {status_text} successfully',
                'rule_id': rule_id,
                'rule_name': rule_name,
                'is_active': new_status
            }), 200
        else:
            return jsonify({'error': 'Failed to toggle rule status'}), 500
            
    except Exception as e:
        logger.error(f"Error toggling rule status for {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/types', methods=['GET'])
def get_rule_types():
    """Get available rule types and their descriptions"""
    try:
        rule_types = {
            'Process': {
                'name': 'Process Rules',
                'description': 'Monitor process execution, command lines, and process behavior',
                'conditions': ['ProcessName', 'ProcessPath', 'CommandLine', 'ParentProcess'],
                'examples': ['Detect suspicious processes', 'Monitor admin tools usage', 'Block malware execution']
            },
            'File': {
                'name': 'File Rules', 
                'description': 'Monitor file system activities and file access patterns',
                'conditions': ['FileName', 'FilePath', 'FileExtension', 'EventType'],
                'examples': ['Detect ransomware file changes', 'Monitor sensitive file access', 'Block file execution']
            },
            'Network': {
                'name': 'Network Rules',
                'description': 'Monitor network connections and traffic patterns', 
                'conditions': ['IPAddress', 'Port', 'Protocol', 'Direction'],
                'examples': ['Detect C&C communications', 'Block suspicious IPs', 'Monitor data exfiltration']
            }
        }
        
        # Get counts for each type
        rule_db = RuleDB()
        for rule_type in rule_types:
            rules = rule_db.get_rules_by_type(rule_type)
            rule_types[rule_type]['total_rules'] = len(rules)
            rule_types[rule_type]['active_rules'] = len([r for r in rules if r.get('IsActive')])
        
        return jsonify({
            'status': 'success',
            'data': rule_types
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rule types: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/severities', methods=['GET'])
def get_rule_severities():
    """Get available rule severities"""
    try:
        severities = {
            'Critical': {
                'level': 4,
                'description': 'Immediate threat requiring urgent attention',
                'color': '#dc3545',
                'examples': ['System compromise', 'Data breach', 'Malware execution']
            },
            'High': {
                'level': 3, 
                'description': 'Serious security concern requiring prompt action',
                'color': '#fd7e14',
                'examples': ['Privilege escalation', 'Suspicious network activity', 'Policy violations']
            },
            'Medium': {
                'level': 2,
                'description': 'Potential security issue requiring investigation',
                'color': '#ffc107', 
                'examples': ['Unusual process activity', 'Configuration changes', 'Failed authentications']
            },
            'Low': {
                'level': 1,
                'description': 'Informational event for monitoring purposes',
                'color': '#28a745',
                'examples': ['Normal admin activities', 'Baseline monitoring', 'Compliance logging']
            }
        }
        
        # Get counts for each severity
        rule_db = RuleDB()
        all_rules = rule_db.get_all_rules()
        
        for severity in severities:
            severity_rules = [r for r in all_rules if r.get('Severity') == severity]
            severities[severity]['total_rules'] = len(severity_rules)
            severities[severity]['active_rules'] = len([r for r in severity_rules if r.get('IsActive')])
        
        return jsonify({
            'status': 'success',
            'data': severities
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rule severities: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/actions', methods=['GET'])
def get_rule_actions():
    """Get available rule actions"""
    try:
        actions = {
            'Alert': {
                'description': 'Generate alert notification only',
                'impact': 'Low - Monitoring only',
                'automated': False
            },
            'AlertAndBlock': {
                'description': 'Generate alert and attempt to block the activity',
                'impact': 'High - May interrupt operations', 
                'automated': True
            },
            'Block': {
                'description': 'Block the activity without generating alert',
                'impact': 'High - Silent blocking',
                'automated': True
            },
            'Monitor': {
                'description': 'Log activity for analysis without alerting',
                'impact': 'None - Silent monitoring',
                'automated': False
            }
        }
        
        # Get counts for each action
        rule_db = RuleDB()
        all_rules = rule_db.get_all_rules()
        
        for action in actions:
            action_rules = [r for r in all_rules if r.get('Action') == action]
            actions[action]['total_rules'] = len(action_rules)
            actions[action]['active_rules'] = len([r for r in action_rules if r.get('IsActive')])
        
        return jsonify({
            'status': 'success',
            'data': actions
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rule actions: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/statistics', methods=['GET'])
def get_rules_statistics():
    """Get comprehensive rule statistics"""
    try:
        rule_db = RuleDB()
        alert_db = AlertDB()
        
        # Get all rules
        all_rules = rule_db.get_all_rules()
        
        # Basic counts
        stats = {
            'total_rules': len(all_rules),
            'active_rules': len([r for r in all_rules if r.get('IsActive')]),
            'inactive_rules': len([r for r in all_rules if not r.get('IsActive')]),
            'global_rules': len([r for r in all_rules if r.get('IsGlobal')]),
            'agent_specific_rules': len([r for r in all_rules if not r.get('IsGlobal')])
        }
        
        # Distribution by type
        stats['by_type'] = {}
        stats['by_severity'] = {}
        stats['by_action'] = {}
        stats['by_os'] = {}
        
        for rule in all_rules:
            rule_type = rule.get('RuleType', 'Unknown')
            severity = rule.get('Severity', 'Unknown')
            action = rule.get('Action', 'Unknown')
            os_type = rule.get('OSType', 'All')
            
            stats['by_type'][rule_type] = stats['by_type'].get(rule_type, 0) + 1
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            stats['by_action'][action] = stats['by_action'].get(action, 0) + 1
            stats['by_os'][os_type] = stats['by_os'].get(os_type, 0) + 1
        
        # Alert statistics (last 30 days)
        alert_filters = {
            'start_time': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
        }
        recent_alerts = alert_db.get_alerts(alert_filters, 10000)
        
        stats['alerts_generated'] = len(recent_alerts)
        
        # Most triggered rules
        rule_alert_counts = {}
        for alert in recent_alerts:
            rule_id = alert.get('RuleID')
            if rule_id:
                rule_alert_counts[rule_id] = rule_alert_counts.get(rule_id, 0) + 1
        
        # Get top 5 most triggered rules
        top_rules = sorted(rule_alert_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        stats['most_triggered_rules'] = []
        
        for rule_id, alert_count in top_rules:
            rule = rule_db.get_rule_by_id(rule_id)
            if rule:
                stats['most_triggered_rules'].append({
                    'rule_id': rule_id,
                    'rule_name': rule.get('RuleName', f'Rule {rule_id}'),
                    'alert_count': alert_count,
                    'severity': rule.get('Severity', 'Unknown'),
                    'rule_type': rule.get('RuleType', 'Unknown')
                })
        
        # Performance metrics
        stats['performance'] = {
            'avg_alerts_per_rule': round(len(recent_alerts) / max(len(all_rules), 1), 2),
            'rules_never_triggered': len([r for r in all_rules if r.get('RuleID') not in rule_alert_counts]),
            'rules_with_high_activity': len([r for r in rule_alert_counts.values() if r > 10])
        }
        
        stats['timestamp'] = datetime.now().isoformat()
        
        return jsonify({
            'status': 'success',
            'data': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rule statistics: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/test', methods=['POST'])
def test_rule():
    """Test rule against sample data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        rule_id = data.get('rule_id')
        test_data = data.get('test_data', {})
        
        if not rule_id:
            return jsonify({'error': 'rule_id is required'}), 400
        
        if not test_data:
            return jsonify({'error': 'test_data is required'}), 400
        
        rule_db = RuleDB()
        
        # Get rule details
        rule = rule_db.get_rule_by_id(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Test rule violation
        violation_result = rule_db.check_rule_violation(rule_id, test_data)
        
        result = {
            'rule_id': rule_id,
            'rule_name': rule.get('RuleName'),
            'rule_type': rule.get('RuleType'),
            'test_data': test_data,
            'violation_detected': violation_result is not None,
            'test_timestamp': datetime.now().isoformat()
        }
        
        if violation_result:
            result['violation_details'] = violation_result
            result['would_generate_alert'] = True
            result['alert_severity'] = rule.get('Severity')
            result['recommended_action'] = rule.get('Action')
        else:
            result['violation_details'] = None
            result['would_generate_alert'] = False
            result['message'] = 'No rule violation detected with provided test data'
        
        return jsonify({
            'status': 'success',
            'data': result
        }), 200
        
    except Exception as e:
        logger.error(f"Error testing rule: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/bulk-actions', methods=['POST'])
def bulk_rule_actions():
    """Perform bulk actions on multiple rules"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        action = data.get('action')
        rule_ids = data.get('rule_ids', [])
        
        if not action:
            return jsonify({'error': 'action is required'}), 400
        if not rule_ids or not isinstance(rule_ids, list):
            return jsonify({'error': 'rule_ids must be a non-empty list'}), 400
        
        rule_db = RuleDB()
        results = {
            'success': [],
            'failed': [],
            'action': action
        }
        
        for rule_id in rule_ids:
            try:
                if action == 'activate':
                    success = rule_db.update_rule(rule_id, {'IsActive': True})
                elif action == 'deactivate':
                    success = rule_db.update_rule(rule_id, {'IsActive': False})
                elif action == 'delete':
                    success = rule_db.delete_rule(rule_id)
                elif action == 'set_severity':
                    severity = data.get('severity', 'Medium')
                    success = rule_db.update_rule(rule_id, {'Severity': severity})
                elif action == 'set_action':
                    rule_action = data.get('rule_action', 'Alert')
                    success = rule_db.update_rule(rule_id, {'Action': rule_action})
                else:
                    results['failed'].append({'rule_id': rule_id, 'error': f'Unknown action: {action}'})
                    continue
                
                if success:
                    results['success'].append(rule_id)
                else:
                    results['failed'].append({'rule_id': rule_id, 'error': 'Operation failed'})
                    
            except Exception as e:
                results['failed'].append({'rule_id': rule_id, 'error': str(e)})
        
        return jsonify({
            'status': 'completed',
            'results': results,
            'summary': {
                'total': len(rule_ids),
                'success_count': len(results['success']),
                'failed_count': len(results['failed'])
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error performing bulk rule actions: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/export', methods=['GET'])
def export_rules():
    """Export rules in various formats"""
    try:
        export_format = request.args.get('format', 'json').lower()
        
        if export_format not in ['json', 'csv']:
            return jsonify({'error': 'Supported formats: json, csv'}), 400
        
        # Get filter parameters
        filters = {}
        for param in ['rule_type', 'severity', 'is_active', 'action']:
            value = request.args.get(param)
            if value is not None:
                if param == 'is_active':
                    filters[param] = value.lower() in ['true', '1', 'yes']
                else:
                    filters[param] = value
        
        rule_db = RuleDB()
        rules = rule_db.get_rules_dashboard(filters)
        
        if export_format == 'json':
            return jsonify({
                'status': 'success',
                'export_format': 'json',
                'export_time': datetime.now().isoformat(),
                'filters': filters,
                'data': rules,
                'count': len(rules)
            }), 200
        
        elif export_format == 'csv':
            import csv
            import io
            
            # Create CSV content
            output = io.StringIO()
            if rules:
                fieldnames = ['RuleID', 'RuleName', 'RuleType', 'Description', 'Severity', 
                             'Action', 'IsActive', 'IsGlobal', 'OSType', 'CreatedAt', 'UpdatedAt']
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                
                for rule in rules:
                    # Create a clean row with only the desired fields
                    row = {}
                    for field in fieldnames:
                        value = rule.get(field, '')
                        if isinstance(value, (dict, list)):
                            row[field] = json.dumps(value)
                        else:
                            row[field] = value
                    writer.writerow(row)
            
            csv_content = output.getvalue()
            output.close()
            
            # Return CSV as download
            from flask import Response
            return Response(
                csv_content,
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment; filename=rules_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                }
            )
        
    except Exception as e:
        logger.error(f"Error exporting rules: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/templates', methods=['GET'])
def get_rule_templates():
    """Get rule templates for different scenarios"""
    try:
        templates = {
            'process_monitoring': {
                'name': 'Suspicious Process Monitoring',
                'description': 'Monitor execution of potentially suspicious processes',
                'rule_type': 'Process',
                'severity': 'High',
                'action': 'Alert',
                'template': {
                    'RuleName': 'Suspicious Process Detection',
                    'RuleType': 'Process',
                    'Description': 'Detects execution of suspicious system tools and processes',
                    'Severity': 'High',
                    'Action': 'Alert',
                    'IsActive': True,
                    'IsGlobal': True,
                    'OSType': 'All'
                },
                'conditions_example': [
                    {'ProcessName': 'cmd.exe'},
                    {'ProcessName': 'powershell.exe'},
                    {'ProcessName': 'wmic.exe'}
                ]
            },
            'file_protection': {
                'name': 'Critical File Protection',
                'description': 'Protect critical system and application files',
                'rule_type': 'File',
                'severity': 'Critical',
                'action': 'AlertAndBlock',
                'template': {
                    'RuleName': 'Critical File Protection',
                    'RuleType': 'File',
                    'Description': 'Prevents unauthorized modification of critical files',
                    'Severity': 'Critical',
                    'Action': 'AlertAndBlock',
                    'IsActive': True,
                    'IsGlobal': True,
                    'OSType': 'All'
                },
                'conditions_example': [
                    {'FilePath': '*\\system32\\*'},
                    {'FilePath': '*\\Windows\\*'},
                    {'FileName': '*.exe'}
                ]
            },
            'network_monitoring': {
                'name': 'Network Traffic Monitoring',
                'description': 'Monitor suspicious network connections and traffic',
                'rule_type': 'Network',
                'severity': 'Medium',
                'action': 'Alert',
                'template': {
                    'RuleName': 'Suspicious Network Activity',
                    'RuleType': 'Network',
                    'Description': 'Detects connections to suspicious ports and addresses',
                    'Severity': 'Medium',
                    'Action': 'Alert',
                    'IsActive': True,
                    'IsGlobal': True,
                    'OSType': 'All'
                },
                'conditions_example': [
                    {'Port': 22},
                    {'Port': 3389},
                    {'Protocol': 'TCP'}
                ]
            },
            'malware_detection': {
                'name': 'Malware Detection',
                'description': 'Detect common malware behaviors and indicators',
                'rule_type': 'Process',
                'severity': 'Critical',
                'action': 'AlertAndBlock',
                'template': {
                    'RuleName': 'Malware Behavior Detection',
                    'RuleType': 'Process',
                    'Description': 'Detects processes exhibiting malware-like behavior',
                    'Severity': 'Critical',
                    'Action': 'AlertAndBlock',
                    'IsActive': True,
                    'IsGlobal': True,
                    'OSType': 'All'
                },
                'conditions_example': [
                    {'ProcessName': '*cryptolocker*'},
                    {'ProcessName': '*ransomware*'},
                    {'CommandLine': '*vssadmin delete shadows*'}
                ]
            },
            'compliance_monitoring': {
                'name': 'Compliance Monitoring',
                'description': 'Monitor activities for compliance requirements',
                'rule_type': 'File',
                'severity': 'Low',
                'action': 'Monitor',
                'template': {
                    'RuleName': 'Compliance File Access',
                    'RuleType': 'File',
                    'Description': 'Monitors access to compliance-sensitive files',
                    'Severity': 'Low',
                    'Action': 'Monitor',
                    'IsActive': True,
                    'IsGlobal': False,
                    'OSType': 'All'
                },
                'conditions_example': [
                    {'FilePath': '*\\Documents\\Confidential\\*'},
                    {'FilePath': '*\\PII\\*'},
                    {'EventType': 'Access'}
                ]
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': templates,
            'count': len(templates)
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting rule templates: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/import', methods=['POST'])
def import_rules():
    """Import rules from file or JSON data"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        import_data = data.get('rules', [])
        if not isinstance(import_data, list):
            return jsonify({'error': 'Rules data must be a list'}), 400
        
        rule_db = RuleDB()
        results = {
            'success': [],
            'failed': [],
            'total': len(import_data)
        }
        
        for rule_data in import_data:
            try:
                # Validate required fields
                if not isinstance(rule_data, dict):
                    results['failed'].append({
                        'rule': rule_data,
                        'error': 'Rule data must be a dictionary'
                    })
                    continue
                
                rule_name = (rule_data.get('RuleName') or rule_data.get('rule_name') or 
                           rule_data.get('name', 'Imported Rule'))
                
                # Check if rule with same name already exists
                existing_rules = rule_db.get_all_rules()
                existing_names = [r.get('RuleName', '') for r in existing_rules]
                
                if rule_name in existing_names:
                    # Add suffix to make name unique
                    counter = 1
                    original_name = rule_name
                    while rule_name in existing_names:
                        rule_name = f"{original_name} ({counter})"
                        counter += 1
                    rule_data['RuleName'] = rule_name
                
                # Import the rule
                if rule_db.create_rule(rule_data):
                    results['success'].append({
                        'rule_name': rule_name,
                        'original_name': rule_data.get('RuleName', rule_name)
                    })
                else:
                    results['failed'].append({
                        'rule': rule_data,
                        'error': 'Failed to create rule in database'
                    })
                    
            except Exception as e:
                results['failed'].append({
                    'rule': rule_data,
                    'error': str(e)
                })
        
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
        logger.error(f"Error importing rules: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/validate', methods=['POST'])
def validate_rule():
    """Validate rule data before creation"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        errors = []
        warnings = []
        
        # Check required fields
        required_fields = ['RuleName', 'RuleType', 'Description', 'Severity']
        for field in required_fields:
            value = (data.get(field) or data.get(field.lower()) or 
                    data.get(field.replace('Rule', '').lower()))
            if not value:
                errors.append(f"Required field '{field}' is missing or empty")
        
        # Validate field values
        rule_type = (data.get('RuleType') or data.get('rule_type') or 
                    data.get('type', '')).strip()
        if rule_type and rule_type not in ['Process', 'File', 'Network']:
            errors.append(f"Invalid RuleType '{rule_type}'. Must be one of: Process, File, Network")
        
        severity = (data.get('Severity') or data.get('severity') or 
                   data.get('level', '')).strip()
        if severity and severity not in ['Low', 'Medium', 'High', 'Critical']:
            errors.append(f"Invalid Severity '{severity}'. Must be one of: Low, Medium, High, Critical")
        
        action = (data.get('Action') or data.get('action') or 
                 data.get('response', '')).strip()
        if action and action not in ['Alert', 'AlertAndBlock', 'Block', 'Monitor']:
            errors.append(f"Invalid Action '{action}'. Must be one of: Alert, AlertAndBlock, Block, Monitor")
        
        os_type = (data.get('OSType') or data.get('os_type') or 
                  data.get('platform', '')).strip()
        if os_type and os_type not in ['Windows', 'Linux', 'All']:
            warnings.append(f"OSType '{os_type}' is not standard. Recommended: Windows, Linux, All")
        
        # Check rule name uniqueness
        rule_name = (data.get('RuleName') or data.get('rule_name') or 
                    data.get('name', '')).strip()
        if rule_name:
            rule_db = RuleDB()
            existing_rules = rule_db.get_all_rules()
            existing_names = [r.get('RuleName', '') for r in existing_rules]
            
            if rule_name in existing_names:
                warnings.append(f"Rule name '{rule_name}' already exists. Consider using a unique name.")
        
        # Validate conditions if provided
        conditions_fields = ['WindowsConditions', 'LinuxConditions', 'conditions']
        for condition_field in conditions_fields:
            conditions = data.get(condition_field)
            if conditions:
                if not isinstance(conditions, list):
                    errors.append(f"{condition_field} must be a list of condition objects")
                else:
                    for i, condition in enumerate(conditions):
                        if not isinstance(condition, dict):
                            errors.append(f"{condition_field}[{i}] must be a dictionary")
                        elif not any(condition.values()):
                            warnings.append(f"{condition_field}[{i}] has no meaningful conditions")
        
        # Performance warnings
        description = (data.get('Description') or data.get('description', '')).strip()
        if len(description) > 500:
            warnings.append("Description is very long. Consider keeping it concise for better readability.")
        
        is_global = data.get('IsGlobal', data.get('is_global', True))
        if is_global and severity in ['Critical', 'High']:
            warnings.append("Global rules with Critical/High severity may generate many alerts. Consider testing first.")
        
        # Create validation result
        is_valid = len(errors) == 0
        
        result = {
            'is_valid': is_valid,
            'errors': errors,
            'warnings': warnings,
            'validation_summary': {
                'error_count': len(errors),
                'warning_count': len(warnings),
                'can_create': is_valid
            },
            'validated_fields': {
                'rule_name': rule_name,
                'rule_type': rule_type,
                'severity': severity,
                'action': action,
                'os_type': os_type,
                'is_global': is_global
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': result
        }), 200
        
    except Exception as e:
        logger.error(f"Error validating rule: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/<int:rule_id>/agents', methods=['GET'])
def get_rule_agents(rule_id):
    """Get agents that have this rule assigned"""
    try:
        rule_db = RuleDB()
        agent_db = AgentDB()
        
        # Check if rule exists
        rule = rule_db.get_rule_by_id(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Get agents with this rule assigned
        from database.connection import DatabaseConnection
        db = DatabaseConnection()
        db.connect()
        
        query = """
            SELECT ar.Hostname, a.OSType, a.Status, a.LastSeen, a.IPAddress
            FROM AgentRules ar
            LEFT JOIN Agents a ON ar.Hostname = a.Hostname
            WHERE ar.RuleID = ? AND ar.IsActive = 1
            ORDER BY ar.Hostname
        """
        
        cursor = db.execute_query(query, [rule_id])
        agents = []
        
        if cursor:
            columns = [column[0] for column in cursor.description]
            for row in cursor.fetchall():
                agent_dict = {}
                for i, value in enumerate(row):
                    col_name = columns[i]
                    if hasattr(value, 'strftime'):
                        agent_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        agent_dict[col_name] = value
                agents.append(agent_dict)
        
        # Add rule applicability info
        rule_info = {
            'rule_id': rule_id,
            'rule_name': rule.get('RuleName'),
            'rule_type': rule.get('RuleType'),
            'is_global': rule.get('IsGlobal'),
            'os_type': rule.get('OSType')
        }
        
        return jsonify({
            'status': 'success',
            'data': agents,
            'count': len(agents),
            'rule_info': rule_info
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting agents for rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/<int:rule_id>/alerts', methods=['GET'])
def get_rule_alerts(rule_id):
    """Get alerts generated by this rule"""
    try:
        rule_db = RuleDB()
        alert_db = AlertDB()
        
        # Check if rule exists
        rule = rule_db.get_rule_by_id(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        # Get query parameters
        days = int(request.args.get('days', 30))
        status = request.args.get('status')
        hostname = request.args.get('hostname')
        limit = int(request.args.get('limit', 100))
        
        # Build filters
        filters = {
            'rule_id': rule_id,
            'start_time': (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        if status:
            filters['status'] = status
        if hostname:
            filters['hostname'] = hostname
        
        # Get alerts
        alerts = alert_db.get_alerts(filters, limit)
        
        # Add summary statistics
        summary = {
            'total_alerts': len(alerts),
            'by_status': {},
            'by_severity': {},
            'by_hostname': {},
            'time_range_days': days
        }
        
        for alert in alerts:
            status = alert.get('Status', 'Unknown')
            severity = alert.get('Severity', 'Unknown')
            hostname = alert.get('Hostname', 'Unknown')
            
            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            summary['by_hostname'][hostname] = summary['by_hostname'].get(hostname, 0) + 1
        
        rule_info = {
            'rule_id': rule_id,
            'rule_name': rule.get('RuleName'),
            'rule_type': rule.get('RuleType'),
            'severity': rule.get('Severity')
        }
        
        return jsonify({
            'status': 'success',
            'data': alerts,
            'count': len(alerts),
            'summary': summary,
            'rule_info': rule_info,
            'filters_applied': filters
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting alerts for rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

@rules_api.route('/conditions/<int:rule_id>', methods=['GET'])
def get_rule_conditions(rule_id):
    """Get detailed conditions for a specific rule"""
    try:
        rule_db = RuleDB()
        
        # Check if rule exists
        rule = rule_db.get_rule_by_id(rule_id)
        if not rule:
            return jsonify({'error': 'Rule not found'}), 404
        
        rule_type = rule.get('RuleType', '')
        conditions = []
        
        # Load conditions based on rule type
        try:
            if rule_type == 'Process':
                conditions = rule_db._load_process_conditions(rule_id)
            elif rule_type == 'File':
                conditions = rule_db._load_file_conditions(rule_id)
            elif rule_type == 'Network':
                conditions = rule_db._load_network_conditions(rule_id)
        except Exception as e:
            logger.warning(f"Could not load conditions for rule {rule_id}: {e}")
        
        # Format conditions for better readability
        formatted_conditions = []
        for condition in conditions:
            formatted_condition = {
                'raw': condition,
                'description': _format_condition_description(rule_type, condition),
                'field_count': len([v for v in condition.values() if v])
            }
            formatted_conditions.append(formatted_condition)
        
        rule_info = {
            'rule_id': rule_id,
            'rule_name': rule.get('RuleName'),
            'rule_type': rule_type,
            'description': rule.get('Description')
        }
        
        return jsonify({
            'status': 'success',
            'data': formatted_conditions,
            'count': len(formatted_conditions),
            'rule_info': rule_info
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting conditions for rule {rule_id}: {e}")
        return jsonify({'error': str(e)}), 500

def _format_condition_description(rule_type, condition):
    """Format condition into human-readable description"""
    try:
        descriptions = []
        
        if rule_type == 'Process':
            if condition.get('ProcessName'):
                descriptions.append(f"Process name matches '{condition['ProcessName']}'")
            if condition.get('ProcessPath'):
                descriptions.append(f"Process path matches '{condition['ProcessPath']}'")
                
        elif rule_type == 'File':
            if condition.get('FileName'):
                descriptions.append(f"File name matches '{condition['FileName']}'")
            if condition.get('FilePath'):
                descriptions.append(f"File path matches '{condition['FilePath']}'")
                
        elif rule_type == 'Network':
            if condition.get('IPAddress'):
                descriptions.append(f"IP address matches '{condition['IPAddress']}'")
            if condition.get('Port'):
                descriptions.append(f"Port equals {condition['Port']}")
            if condition.get('Protocol'):
                descriptions.append(f"Protocol is '{condition['Protocol']}'")
        
        return ' AND '.join(descriptions) if descriptions else 'No specific conditions'
        
    except Exception as e:
        return 'Could not format condition description'

@rules_api.route('/cleanup', methods=['POST'])
def cleanup_unused_rules():
    """Clean up unused or inactive rules"""
    try:
        data = request.get_json() or {}
        
        # Options for cleanup
        delete_inactive = data.get('delete_inactive', False)
        delete_never_triggered = data.get('delete_never_triggered', False)
        inactive_days_threshold = data.get('inactive_days_threshold', 90)
        
        rule_db = RuleDB()
        alert_db = AlertDB()
        
        # Get all rules
        all_rules = rule_db.get_all_rules()
        
        cleanup_results = {
            'inactive_rules_deleted': 0,
            'never_triggered_rules_deleted': 0,
            'total_rules_before': len(all_rules),
            'rules_processed': []
        }
        
        cutoff_date = (datetime.now() - timedelta(days=inactive_days_threshold)).strftime('%Y-%m-%d %H:%M:%S')
        
        for rule in all_rules:
            rule_id = rule.get('RuleID')
            rule_name = rule.get('RuleName', f'Rule {rule_id}')
            is_active = rule.get('IsActive', False)
            
            should_delete = False
            delete_reason = ""
            
            # Check if rule should be deleted due to inactivity
            if delete_inactive and not is_active:
                # Check when rule was last updated
                updated_at = rule.get('UpdatedAt')
                if updated_at:
                    try:
                        if isinstance(updated_at, str):
                            updated_date = datetime.strptime(updated_at, '%Y-%m-%d %H:%M:%S')
                        else:
                            updated_date = updated_at
                        
                        if updated_date.strftime('%Y-%m-%d %H:%M:%S') < cutoff_date:
                            should_delete = True
                            delete_reason = f"Inactive for over {inactive_days_threshold} days"
                    except:
                        pass
            
            # Check if rule has never triggered alerts
            if delete_never_triggered and not should_delete:
                alert_filters = {'rule_id': rule_id}
                rule_alerts = alert_db.get_alerts(alert_filters, 1)
                
                if len(rule_alerts) == 0:
                    should_delete = True
                    delete_reason = "Never triggered any alerts"
            
            # Perform deletion
            if should_delete:
                try:
                    success = rule_db.delete_rule(rule_id)
                    if success:
                        if delete_reason.startswith("Inactive"):
                            cleanup_results['inactive_rules_deleted'] += 1
                        elif delete_reason.startswith("Never"):
                            cleanup_results['never_triggered_rules_deleted'] += 1
                        
                        cleanup_results['rules_processed'].append({
                            'rule_id': rule_id,
                            'rule_name': rule_name,
                            'action': 'deleted',
                            'reason': delete_reason
                        })
                    else:
                        cleanup_results['rules_processed'].append({
                            'rule_id': rule_id,
                            'rule_name': rule_name,
                            'action': 'failed_to_delete',
                            'reason': delete_reason
                        })
                except Exception as e:
                    cleanup_results['rules_processed'].append({
                        'rule_id': rule_id,
                        'rule_name': rule_name,
                        'action': 'error',
                        'reason': f"Error: {str(e)}"
                    })
        
        # Final statistics
        cleanup_results['total_rules_after'] = cleanup_results['total_rules_before'] - (
            cleanup_results['inactive_rules_deleted'] + 
            cleanup_results['never_triggered_rules_deleted']
        )
        
        cleanup_results['cleanup_summary'] = {
            'total_deleted': cleanup_results['inactive_rules_deleted'] + cleanup_results['never_triggered_rules_deleted'],
            'cleanup_date': datetime.now().isoformat(),
            'criteria_used': {
                'delete_inactive': delete_inactive,
                'delete_never_triggered': delete_never_triggered,
                'inactive_days_threshold': inactive_days_threshold
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': cleanup_results
        }), 200
        
    except Exception as e:
        logger.error(f"Error cleaning up rules: {e}")
        return jsonify({'error': str(e)}), 500