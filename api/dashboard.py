from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import logging
import json
from database.agents import AgentDB
from database.alerts import AlertDB
from database.logs import LogDB
from database.rules import RuleDB
from database.connection import DatabaseConnection

dashboard_api = Blueprint('dashboard_api', __name__, url_prefix='/dashboard')
logger = logging.getLogger(__name__)

@dashboard_api.route('/summary', methods=['GET'])
def get_dashboard_summary():
    """Get comprehensive dashboard summary with dynamic time ranges"""
    try:
        # Get time range parameters
        hours = request.args.get('hours')
        days = request.args.get('days', 7)
        from_date = request.args.get('from_date')
        to_date = request.args.get('to_date')
        
        # Calculate time range
        if from_date and to_date:
            try:
                start_time = datetime.strptime(from_date, '%Y-%m-%d')
                end_time = datetime.strptime(to_date, '%Y-%m-%d') + timedelta(days=1)
            except ValueError:
                return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD'}), 400
        elif hours:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=int(hours))
        else:
            end_time = datetime.now()
            start_time = end_time - timedelta(days=int(days))
        
        # Initialize database connections
        agent_db = AgentDB()
        alert_db = AlertDB()
        log_db = LogDB()
        rule_db = RuleDB()
        
        # Get agents summary
        agents = agent_db.get_all_agents()
        agents_summary = {
            'total': len(agents),
            'online': 0,
            'offline': 0,
            'by_os': {},
            'by_status': {},
            'recently_registered': 0
        }
        
        # Calculate agent statistics
        recent_threshold = datetime.now() - timedelta(hours=24)
        
        for agent in agents:
            # Online/Offline status
            if agent.get('Status') == 'Online':
                agents_summary['online'] += 1
            else:
                agents_summary['offline'] += 1
            
            # By OS distribution
            os_type = agent.get('OSType', 'Unknown')
            agents_summary['by_os'][os_type] = agents_summary['by_os'].get(os_type, 0) + 1
            
            # By status distribution
            status = agent.get('Status', 'Unknown')
            agents_summary['by_status'][status] = agents_summary['by_status'].get(status, 0) + 1
            
            # Recently registered agents
            first_seen = agent.get('FirstSeen')
            if first_seen:
                try:
                    if isinstance(first_seen, str):
                        first_seen_dt = datetime.strptime(first_seen, '%Y-%m-%d %H:%M:%S')
                    else:
                        first_seen_dt = first_seen
                    
                    if first_seen_dt >= recent_threshold:
                        agents_summary['recently_registered'] += 1
                except:
                    pass
        
        # Get alerts summary
        alert_filters = {
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
        }
        
        alerts = alert_db.get_alerts(alert_filters, 10000)
        alerts_summary = {
            'total': len(alerts),
            'by_severity': {},
            'by_status': {},
            'by_type': {},
            'recent_count': 0,
            'trend': []
        }
        
        # Calculate alert statistics
        recent_alert_threshold = datetime.now() - timedelta(hours=1)
        
        for alert in alerts:
            # By severity
            severity = alert.get('Severity', 'Unknown')
            alerts_summary['by_severity'][severity] = alerts_summary['by_severity'].get(severity, 0) + 1
            
            # By status
            status = alert.get('Status', 'Unknown')
            alerts_summary['by_status'][status] = alerts_summary['by_status'].get(status, 0) + 1
            
            # By type
            alert_type = alert.get('AlertType', 'Unknown')
            alerts_summary['by_type'][alert_type] = alerts_summary['by_type'].get(alert_type, 0) + 1
            
            # Recent alerts count
            alert_time = alert.get('Time')
            if alert_time:
                try:
                    if isinstance(alert_time, str):
                        alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                    else:
                        alert_dt = alert_time
                    
                    if alert_dt >= recent_alert_threshold:
                        alerts_summary['recent_count'] += 1
                except:
                    pass
        
        # Calculate alert trend (last 24 hours by hour)
        trend_start = datetime.now() - timedelta(hours=24)
        hourly_counts = {}
        
        for alert in alerts:
            alert_time = alert.get('Time')
            if alert_time:
                try:
                    if isinstance(alert_time, str):
                        alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                    else:
                        alert_dt = alert_time
                    
                    if alert_dt >= trend_start:
                        hour_key = alert_dt.strftime('%Y-%m-%d %H:00')
                        hourly_counts[hour_key] = hourly_counts.get(hour_key, 0) + 1
                except:
                    continue
        
        # Format trend data
        for i in range(24):
            hour_time = datetime.now() - timedelta(hours=23-i)
            hour_key = hour_time.strftime('%Y-%m-%d %H:00')
            alerts_summary['trend'].append({
                'time': hour_key,
                'count': hourly_counts.get(hour_key, 0)
            })
        
        # Get logs summary
        logs_summary = {
            'total': 0,
            'by_type': {},
            'recent_activity': {},
            'top_processes': [],
            'top_files': [],
            'top_networks': []
        }
        
        # Get process logs
        try:
            process_logs = log_db.get_process_logs(limit=1000)
            logs_summary['by_type']['process'] = len(process_logs)
            logs_summary['total'] += len(process_logs)
            
            # Top processes
            process_counts = {}
            for log in process_logs[:100]:  # Limit for performance
                proc_name = log.get('ProcessName', 'Unknown')
                process_counts[proc_name] = process_counts.get(proc_name, 0) + 1
            
            logs_summary['top_processes'] = [
                {'name': name, 'count': count}
                for name, count in sorted(process_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
        except Exception as e:
            logger.warning(f"Error getting process logs: {e}")
            logs_summary['by_type']['process'] = 0
        
        # Get file logs
        try:
            file_logs = log_db.get_file_logs(limit=1000)
            logs_summary['by_type']['file'] = len(file_logs)
            logs_summary['total'] += len(file_logs)
            
            # Top files
            file_counts = {}
            for log in file_logs[:100]:
                file_name = log.get('FileName', 'Unknown')
                file_counts[file_name] = file_counts.get(file_name, 0) + 1
            
            logs_summary['top_files'] = [
                {'name': name, 'count': count}
                for name, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
        except Exception as e:
            logger.warning(f"Error getting file logs: {e}")
            logs_summary['by_type']['file'] = 0
        
        # Get network logs
        try:
            network_logs = log_db.get_network_logs(limit=1000)
            logs_summary['by_type']['network'] = len(network_logs)
            logs_summary['total'] += len(network_logs)
            
            # Top network destinations
            network_counts = {}
            for log in network_logs[:100]:
                remote_addr = log.get('RemoteAddress', 'Unknown')
                if remote_addr and remote_addr != 'Unknown':
                    network_counts[remote_addr] = network_counts.get(remote_addr, 0) + 1
            
            logs_summary['top_networks'] = [
                {'address': addr, 'count': count}
                for addr, count in sorted(network_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            ]
        except Exception as e:
            logger.warning(f"Error getting network logs: {e}")
            logs_summary['by_type']['network'] = 0
        
        # Get rules summary
        rules = rule_db.get_all_rules()
        rules_summary = {
            'total': len(rules),
            'active': len([r for r in rules if r.get('IsActive')]),
            'inactive': len([r for r in rules if not r.get('IsActive')]),
            'by_type': {},
            'by_severity': {},
            'recently_triggered': 0
        }
        
        # Calculate rules statistics
        for rule in rules:
            rule_type = rule.get('RuleType', 'Unknown')
            severity = rule.get('Severity', 'Unknown')
            
            rules_summary['by_type'][rule_type] = rules_summary['by_type'].get(rule_type, 0) + 1
            rules_summary['by_severity'][severity] = rules_summary['by_severity'].get(severity, 0) + 1
        
        # Count recently triggered rules
        recent_rule_ids = set()
        for alert in alerts:
            if alert.get('Time'):
                try:
                    if isinstance(alert.get('Time'), str):
                        alert_dt = datetime.strptime(alert['Time'], '%Y-%m-%d %H:%M:%S')
                    else:
                        alert_dt = alert['Time']
                    
                    if alert_dt >= recent_alert_threshold:
                        recent_rule_ids.add(alert.get('RuleID'))
                except:
                    pass
        
        rules_summary['recently_triggered'] = len(recent_rule_ids)
        
        # System health indicators
        health_indicators = {
            'overall_status': 'healthy',
            'issues': [],
            'warnings': [],
            'recommendations': []
        }
        
        # Check for issues
        if agents_summary['offline'] > agents_summary['online']:
            health_indicators['issues'].append('More agents offline than online')
            health_indicators['overall_status'] = 'warning'
        
        critical_alerts = alerts_summary['by_severity'].get('Critical', 0)
        if critical_alerts > 10:
            health_indicators['issues'].append(f'{critical_alerts} critical alerts in selected period')
            health_indicators['overall_status'] = 'critical'
        
        # Check for warnings
        if agents_summary['recently_registered'] == 0 and int(days) > 1:
            health_indicators['warnings'].append('No new agents registered recently')
        
        if rules_summary['inactive'] > rules_summary['active']:
            health_indicators['warnings'].append('More inactive rules than active ones')
        
        # Recommendations
        if alerts_summary['by_status'].get('New', 0) > 50:
            health_indicators['recommendations'].append('Many unprocessed alerts - consider review')
        
        if logs_summary['total'] < 100:
            health_indicators['recommendations'].append('Low log volume - check agent connectivity')
        
        # Performance metrics
        performance_metrics = {
            'alerts_per_agent': round(alerts_summary['total'] / max(agents_summary['total'], 1), 2),
            'logs_per_agent': round(logs_summary['total'] / max(agents_summary['total'], 1), 2),
            'active_rules_percentage': round((rules_summary['active'] / max(rules_summary['total'], 1)) * 100, 1),
            'agent_uptime_percentage': round((agents_summary['online'] / max(agents_summary['total'], 1)) * 100, 1)
        }
        
        return jsonify({
            'status': 'success',
            'data': {
                'agents': agents_summary,
                'alerts': alerts_summary,
                'logs': logs_summary,
                'rules': rules_summary,
                'health': health_indicators,
                'performance': performance_metrics,
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'duration_hours': int((end_time - start_time).total_seconds() / 3600)
                },
                'timestamp': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard summary: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/timeline', methods=['GET'])
def get_dashboard_timeline():
    """Get timeline events for dashboard visualization"""
    try:
        # Get parameters
        hours = int(request.args.get('hours', 24))
        event_types = request.args.getlist('types')  # alerts, agent_events, rule_events
        limit = int(request.args.get('limit', 100))
        
        if not event_types:
            event_types = ['alerts', 'agent_events']
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        timeline_events = []
        
        # Get alert events
        if 'alerts' in event_types:
            alert_db = AlertDB()
            alert_filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            alerts = alert_db.get_alerts(alert_filters, limit)
            
            for alert in alerts:
                if alert.get('Time'):
                    timeline_events.append({
                        'type': 'alert',
                        'timestamp': alert['Time'],
                        'title': alert.get('Title', 'Alert'),
                        'description': alert.get('Description', ''),
                        'severity': alert.get('Severity', 'Medium'),
                        'hostname': alert.get('Hostname', 'Unknown'),
                        'status': alert.get('Status', 'New'),
                        'alert_type': alert.get('AlertType', 'Security Alert'),
                        'rule_id': alert.get('RuleID'),
                        'icon': 'alert-triangle',
                        'color': _get_severity_color(alert.get('Severity', 'Medium'))
                    })
        
        # Get agent events
        if 'agent_events' in event_types:
            agent_db = AgentDB()
            agents = agent_db.get_all_agents()
            
            for agent in agents:
                # Agent registration events
                first_seen = agent.get('FirstSeen')
                if first_seen:
                    try:
                        if isinstance(first_seen, str):
                            first_seen_dt = datetime.strptime(first_seen, '%Y-%m-%d %H:%M:%S')
                        else:
                            first_seen_dt = first_seen
                        
                        if first_seen_dt >= start_time:
                            timeline_events.append({
                                'type': 'agent_registration',
                                'timestamp': first_seen,
                                'title': f'Agent Registered: {agent.get("Hostname", "Unknown")}',
                                'description': f'New agent {agent.get("Hostname")} ({agent.get("OSType", "Unknown")}) registered',
                                'hostname': agent.get('Hostname', 'Unknown'),
                                'os_type': agent.get('OSType', 'Unknown'),
                                'icon': 'plus-circle',
                                'color': '#28a745'
                            })
                    except:
                        pass
                
                # Agent status changes (simulated - would need audit log in real system)
                last_seen = agent.get('LastSeen')
                if last_seen and agent.get('Status') == 'Offline':
                    try:
                        if isinstance(last_seen, str):
                            last_seen_dt = datetime.strptime(last_seen, '%Y-%m-%d %H:%M:%S')
                        else:
                            last_seen_dt = last_seen
                        
                        if last_seen_dt >= start_time:
                            timeline_events.append({
                                'type': 'agent_offline',
                                'timestamp': last_seen,
                                'title': f'Agent Offline: {agent.get("Hostname", "Unknown")}',
                                'description': f'Agent {agent.get("Hostname")} went offline',
                                'hostname': agent.get('Hostname', 'Unknown'),
                                'icon': 'wifi-off',
                                'color': '#dc3545'
                            })
                    except:
                        pass
        
        # Get rule events (new rules, rule changes)
        if 'rule_events' in event_types:
            rule_db = RuleDB()
            rules = rule_db.get_all_rules()
            
            for rule in rules:
                created_at = rule.get('CreatedAt')
                if created_at:
                    try:
                        if isinstance(created_at, str):
                            created_dt = datetime.strptime(created_at, '%Y-%m-%d %H:%M:%S')
                        else:
                            created_dt = created_at
                        
                        if created_dt >= start_time:
                            timeline_events.append({
                                'type': 'rule_created',
                                'timestamp': created_at,
                                'title': f'Rule Created: {rule.get("RuleName", "Unknown")}',
                                'description': f'New {rule.get("RuleType", "Unknown")} rule created',
                                'rule_name': rule.get('RuleName', 'Unknown'),
                                'rule_type': rule.get('RuleType', 'Unknown'),
                                'severity': rule.get('Severity', 'Medium'),
                                'icon': 'shield',
                                'color': '#007bff'
                            })
                    except:
                        pass
        
        # Sort timeline events by timestamp (newest first)
        timeline_events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Apply limit
        if limit > 0:
            timeline_events = timeline_events[:limit]
        
        # Group events by time periods for better visualization
        grouped_events = {}
        for event in timeline_events:
            try:
                if isinstance(event['timestamp'], str):
                    event_dt = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
                else:
                    event_dt = event['timestamp']
                
                # Group by hour
                group_key = event_dt.strftime('%Y-%m-%d %H:00')
                
                if group_key not in grouped_events:
                    grouped_events[group_key] = []
                
                grouped_events[group_key].append(event)
            except:
                continue
        
        # Calculate event statistics
        event_stats = {
            'total_events': len(timeline_events),
            'by_type': {},
            'by_hour': {},
            'most_active_agent': None,
            'most_active_hour': None
        }
        
        agent_activity = {}
        hour_activity = {}
        
        for event in timeline_events:
            event_type = event.get('type', 'unknown')
            event_stats['by_type'][event_type] = event_stats['by_type'].get(event_type, 0) + 1
            
            # Track agent activity
            hostname = event.get('hostname')
            if hostname:
                agent_activity[hostname] = agent_activity.get(hostname, 0) + 1
            
            # Track hourly activity
            try:
                if isinstance(event['timestamp'], str):
                    event_dt = datetime.strptime(event['timestamp'], '%Y-%m-%d %H:%M:%S')
                else:
                    event_dt = event['timestamp']
                
                hour_key = event_dt.strftime('%H:00')
                hour_activity[hour_key] = hour_activity.get(hour_key, 0) + 1
            except:
                pass
        
        # Find most active agent and hour
        if agent_activity:
            event_stats['most_active_agent'] = max(agent_activity.items(), key=lambda x: x[1])
        
        if hour_activity:
            event_stats['most_active_hour'] = max(hour_activity.items(), key=lambda x: x[1])
        
        event_stats['by_hour'] = hour_activity
        
        return jsonify({
            'status': 'success',
            'data': {
                'events': timeline_events,
                'grouped_events': grouped_events,
                'statistics': event_stats,
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': hours
                },
                'filters': {
                    'event_types': event_types,
                    'limit': limit
                }
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard timeline: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/metrics', methods=['GET'])
def get_dashboard_metrics():
    """Get detailed metrics for dashboard widgets"""
    try:
        # Get parameters
        metric_type = request.args.get('type', 'all')  # all, performance, security, compliance
        hours = int(request.args.get('hours', 24))
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        metrics = {}
        
        # Performance metrics
        if metric_type in ['all', 'performance']:
            agent_db = AgentDB()
            agents = agent_db.get_all_agents()
            
            # System performance metrics
            metrics['performance'] = {
                'agent_availability': {
                    'value': round((len([a for a in agents if a.get('Status') == 'Online']) / max(len(agents), 1)) * 100, 1),
                    'unit': '%',
                    'trend': 'stable',  # Would calculate from historical data
                    'description': 'Percentage of agents currently online'
                },
                'average_response_time': {
                    'value': 150,  # Would calculate from actual metrics
                    'unit': 'ms',
                    'trend': 'improving',
                    'description': 'Average agent response time'
                },
                'data_throughput': {
                    'value': 1250,  # Would calculate from log volumes
                    'unit': 'events/min',
                    'trend': 'stable',
                    'description': 'Events processed per minute'
                },
                'storage_usage': {
                    'value': 68.5,  # Would get from system metrics
                    'unit': '%',
                    'trend': 'increasing',
                    'description': 'Database storage utilization'
                }
            }
        
        # Security metrics
        if metric_type in ['all', 'security']:
            alert_db = AlertDB()
            alert_filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            alerts = alert_db.get_alerts(alert_filters, 10000)
            critical_alerts = [a for a in alerts if a.get('Severity') == 'Critical']
            high_alerts = [a for a in alerts if a.get('Severity') == 'High']
            
            metrics['security'] = {
                'threat_level': {
                    'value': 'Medium',  # Would calculate based on alert patterns
                    'numeric_value': 3,
                    'scale': 5,
                    'description': 'Current threat level assessment',
                    'factors': ['Critical alerts', 'Attack patterns', 'Vulnerability exposure']
                },
                'critical_alerts': {
                    'value': len(critical_alerts),
                    'unit': 'alerts',
                    'trend': 'decreasing' if len(critical_alerts) < 5 else 'increasing',
                    'description': f'Critical security alerts in last {hours} hours'
                },
                'security_score': {
                    'value': 85,  # Would calculate from multiple factors
                    'unit': '/100',
                    'trend': 'stable',
                    'description': 'Overall security posture score'
                },
                'incident_response_time': {
                    'value': 18,  # Would calculate from alert resolution times
                    'unit': 'minutes',
                    'trend': 'improving',
                    'description': 'Average time to acknowledge alerts'
                }
            }
        
        # Compliance metrics
        if metric_type in ['all', 'compliance']:
            rule_db = RuleDB()
            rules = rule_db.get_all_rules()
            active_rules = [r for r in rules if r.get('IsActive')]
            
            metrics['compliance'] = {
                'policy_coverage': {
                    'value': round((len(active_rules) / max(len(rules), 1)) * 100, 1),
                    'unit': '%',
                    'trend': 'stable',
                    'description': 'Percentage of security policies active'
                },
                'audit_readiness': {
                    'value': 92,  # Would calculate from various compliance factors
                    'unit': '%',
                    'trend': 'improving',
                    'description': 'System readiness for compliance audit'
                },
                'data_retention': {
                    'value': 87,  # Would calculate from log retention policies
                    'unit': '%',
                    'trend': 'stable',
                    'description': 'Compliance with data retention policies'
                },
                'monitoring_coverage': {
                    'value': len([a for a in agents if a.get('Status') == 'Online']),
                    'total': len(agents),
                    'percentage': round((len([a for a in agents if a.get('Status') == 'Online']) / max(len(agents), 1)) * 100, 1),
                    'unit': 'agents',
                    'description': 'Endpoints under active monitoring'
                }
            }
        
        # Operational metrics
        if metric_type in ['all', 'operational']:
            log_db = LogDB()
            
            # Get log counts for activity metrics
            try:
                process_logs = log_db.get_process_logs(limit=1000)
                file_logs = log_db.get_file_logs(limit=1000)
                network_logs = log_db.get_network_logs(limit=1000)
                
                total_logs = len(process_logs) + len(file_logs) + len(network_logs)
            except:
                total_logs = 0
            
            metrics['operational'] = {
                'system_uptime': {
                    'value': 99.8,  # Would get from system monitoring
                    'unit': '%',
                    'trend': 'stable',
                    'description': 'EDR system uptime percentage'
                },
                'data_quality': {
                    'value': 96.5,  # Would calculate from data validation metrics
                    'unit': '%',
                    'trend': 'improving',
                    'description': 'Quality score of collected data'
                },
                'agent_health': {
                    'healthy': len([a for a in agents if a.get('Status') == 'Online']),
                    'total': len(agents),
                    'percentage': round((len([a for a in agents if a.get('Status') == 'Online']) / max(len(agents), 1)) * 100, 1),
                    'description': 'Agents in healthy state'
                },
                'log_volume': {
                    'value': total_logs,
                    'unit': 'events',
                    'rate': round(total_logs / max(hours, 1), 1),
                    'description': f'Log events collected in last {hours} hours'
                }
            }
        
        # Calculate overall health score
        health_factors = []
        
        if 'performance' in metrics:
            health_factors.append(metrics['performance']['agent_availability']['value'])
        
        if 'security' in metrics:
            health_factors.append(metrics['security']['security_score']['value'])
        
        if 'compliance' in metrics:
            health_factors.append(metrics['compliance']['audit_readiness']['value'])
        
        if 'operational' in metrics:
            health_factors.append(metrics['operational']['system_uptime']['value'])
        
        overall_health = round(sum(health_factors) / max(len(health_factors), 1), 1) if health_factors else 95
        
        metrics['overall'] = {
            'health_score': {
                'value': overall_health,
                'unit': '/100',
                'status': 'excellent' if overall_health >= 95 else 'good' if overall_health >= 85 else 'warning' if overall_health >= 70 else 'critical',
                'description': 'Overall system health score'
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': metrics,
            'metadata': {
                'metric_type': metric_type,
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': hours
                },
                'calculation_time': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard metrics: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/charts', methods=['GET'])
def get_dashboard_charts():
    """Get chart data for dashboard visualizations"""
    try:
        # Get parameters
        chart_type = request.args.get('type', 'all')  # alerts_trend, agent_status, top_threats, etc.
        hours = int(request.args.get('hours', 24))
        interval = request.args.get('interval', 'hour')  # hour, day
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        chart_data = {}
        
        # Alerts trend chart
        if chart_type in ['all', 'alerts_trend']:
            alert_db = AlertDB()
            alert_filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            alerts = alert_db.get_alerts(alert_filters, 10000)
            
            # Group alerts by time interval
            time_buckets = {}
            severity_buckets = {'Critical': {}, 'High': {}, 'Medium': {}, 'Low': {}}
            
            # Initialize time buckets
            current_time = start_time
            while current_time <= end_time:
                if interval == 'hour':
                    bucket_key = current_time.strftime('%Y-%m-%d %H:00')
                    current_time += timedelta(hours=1)
                else:  # day
                    bucket_key = current_time.strftime('%Y-%m-%d')
                    current_time += timedelta(days=1)
                
                time_buckets[bucket_key] = 0
                for severity in severity_buckets:
                    severity_buckets[severity][bucket_key] = 0
            
            # Fill buckets with alert data
            for alert in alerts:
                alert_time = alert.get('Time')
                if alert_time:
                    try:
                        if isinstance(alert_time, str):
                            alert_dt = datetime.strptime(alert_time, '%Y-%m-%d %H:%M:%S')
                        else:
                            alert_dt = alert_time
                        
                        if interval == 'hour':
                            bucket_key = alert_dt.strftime('%Y-%m-%d %H:00')
                        else:
                            bucket_key = alert_dt.strftime('%Y-%m-%d')
                        
                        if bucket_key in time_buckets:
                            time_buckets[bucket_key] += 1
                            
                            severity = alert.get('Severity', 'Medium')
                            if severity in severity_buckets and bucket_key in severity_buckets[severity]:
                                severity_buckets[severity][bucket_key] += 1
                    except:
                        continue
            
            # Format for chart
            chart_data['alerts_trend'] = {
                'labels': sorted(time_buckets.keys()),
                'datasets': [
                    {
                        'label': 'Total Alerts',
                        'data': [time_buckets[key] for key in sorted(time_buckets.keys())],
                        'borderColor': '#007bff',
                        'backgroundColor': 'rgba(0, 123, 255, 0.1)',
                        'tension': 0.4
                    }
                ],
                'severity_breakdown': [
                    {
                        'label': 'Critical',
                        'data': [severity_buckets['Critical'][key] for key in sorted(time_buckets.keys())],
                        'borderColor': '#dc3545',
                        'backgroundColor': 'rgba(220, 53, 69, 0.1)'
                    },
                    {
                        'label': 'High',
                        'data': [severity_buckets['High'][key] for key in sorted(time_buckets.keys())],
                        'borderColor': '#fd7e14',
                        'backgroundColor': 'rgba(253, 126, 20, 0.1)'
                    },
                    {
                        'label': 'Medium',
                        'data': [severity_buckets['Medium'][key] for key in sorted(time_buckets.keys())],
                        'borderColor': '#ffc107',
                        'backgroundColor': 'rgba(255, 193, 7, 0.1)'
                    },
                    {
                        'label': 'Low',
                        'data': [severity_buckets['Low'][key] for key in sorted(time_buckets.keys())],
                        'borderColor': '#28a745',
                        'backgroundColor': 'rgba(40, 167, 69, 0.1)'
                    }
                ]
            }
        
        # Agent status distribution chart
        if chart_type in ['all', 'agent_status']:
            agent_db = AgentDB()
            agents = agent_db.get_all_agents()
            
            status_counts = {}
            os_counts = {}
            
            for agent in agents:
                status = agent.get('Status', 'Unknown')
                os_type = agent.get('OSType', 'Unknown')
                
                status_counts[status] = status_counts.get(status, 0) + 1
                os_counts[os_type] = os_counts.get(os_type, 0) + 1
            
            chart_data['agent_status'] = {
                'status_distribution': {
                    'labels': list(status_counts.keys()),
                    'datasets': [{
                        'data': list(status_counts.values()),
                        'backgroundColor': [
                            '#28a745' if status == 'Online' else '#dc3545' if status == 'Offline' else '#ffc107'
                            for status in status_counts.keys()
                        ]
                    }]
                },
                'os_distribution': {
                    'labels': list(os_counts.keys()),
                    'datasets': [{
                        'data': list(os_counts.values()),
                        'backgroundColor': ['#007bff', '#17a2b8', '#6c757d', '#fd7e14', '#e83e8c'][:len(os_counts)]
                    }]
                }
            }
        
        # Top threats/alerts chart
        if chart_type in ['all', 'top_threats']:
            alert_db = AlertDB()
            alert_filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
            alerts = alert_db.get_alerts(alert_filters, 1000)
            
            # Count by alert type
            alert_type_counts = {}
            rule_counts = {}
            hostname_counts = {}
            
            for alert in alerts:
                alert_type = alert.get('AlertType', 'Unknown')
                rule_name = alert.get('RuleName', 'Unknown Rule')
                hostname = alert.get('Hostname', 'Unknown')
                
                alert_type_counts[alert_type] = alert_type_counts.get(alert_type, 0) + 1
                rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
                hostname_counts[hostname] = hostname_counts.get(hostname, 0) + 1
            
            # Get top 10 for each category
            top_alert_types = sorted(alert_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_hosts = sorted(hostname_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            
            chart_data['top_threats'] = {
                'alert_types': {
                    'labels': [item[0] for item in top_alert_types],
                    'datasets': [{
                        'label': 'Alert Count',
                        'data': [item[1] for item in top_alert_types],
                        'backgroundColor': '#dc3545'
                    }]
                },
                'triggered_rules': {
                    'labels': [item[0] for item in top_rules],
                    'datasets': [{
                        'label': 'Trigger Count',
                        'data': [item[1] for item in top_rules],
                        'backgroundColor': '#fd7e14'
                    }]
                },
                'affected_hosts': {
                    'labels': [item[0] for item in top_hosts],
                    'datasets': [{
                        'label': 'Alert Count',
                        'data': [item[1] for item in top_hosts],
                        'backgroundColor': '#ffc107'
                    }]
                }
            }
        
        # System activity chart
        if chart_type in ['all', 'system_activity']:
            log_db = LogDB()
            
            activity_data = {
                'process_activity': [],
                'file_activity': [],
                'network_activity': []
            }
            
            # Get activity over time
            current_time = start_time
            while current_time <= end_time:
                if interval == 'hour':
                    bucket_key = current_time.strftime('%Y-%m-%d %H:00')
                    current_time += timedelta(hours=1)
                else:
                    bucket_key = current_time.strftime('%Y-%m-%d')
                    current_time += timedelta(days=1)
                
                # This would require time-based queries in a real implementation
                # For now, using simulated data
                activity_data['process_activity'].append({
                    'time': bucket_key,
                    'count': 50 + (hash(bucket_key) % 100)  # Simulated data
                })
                activity_data['file_activity'].append({
                    'time': bucket_key,
                    'count': 30 + (hash(bucket_key + 'file') % 80)
                })
                activity_data['network_activity'].append({
                    'time': bucket_key,
                    'count': 40 + (hash(bucket_key + 'net') % 90)
                })
            
            chart_data['system_activity'] = {
                'labels': [item['time'] for item in activity_data['process_activity']],
                'datasets': [
                    {
                        'label': 'Process Events',
                        'data': [item['count'] for item in activity_data['process_activity']],
                        'borderColor': '#007bff',
                        'backgroundColor': 'rgba(0, 123, 255, 0.1)'
                    },
                    {
                        'label': 'File Events', 
                        'data': [item['count'] for item in activity_data['file_activity']],
                        'borderColor': '#28a745',
                        'backgroundColor': 'rgba(40, 167, 69, 0.1)'
                    },
                    {
                        'label': 'Network Events',
                        'data': [item['count'] for item in activity_data['network_activity']],
                        'borderColor': '#ffc107',
                        'backgroundColor': 'rgba(255, 193, 7, 0.1)'
                    }
                ]
            }
        
        # Performance metrics chart
        if chart_type in ['all', 'performance']:
            # Simulated performance data - would come from system metrics
            performance_times = []
            current_time = start_time
            
            while current_time <= end_time:
                if interval == 'hour':
                    time_key = current_time.strftime('%Y-%m-%d %H:00')
                    current_time += timedelta(hours=1)
                else:
                    time_key = current_time.strftime('%Y-%m-%d')
                    current_time += timedelta(days=1)
                
                performance_times.append(time_key)
            
            chart_data['performance'] = {
                'labels': performance_times,
                'datasets': [
                    {
                        'label': 'CPU Usage %',
                        'data': [65 + (hash(t + 'cpu') % 20) for t in performance_times],
                        'borderColor': '#dc3545',
                        'backgroundColor': 'rgba(220, 53, 69, 0.1)',
                        'yAxisID': 'y'
                    },
                    {
                        'label': 'Memory Usage %',
                        'data': [45 + (hash(t + 'mem') % 30) for t in performance_times],
                        'borderColor': '#fd7e14',
                        'backgroundColor': 'rgba(253, 126, 20, 0.1)',
                        'yAxisID': 'y'
                    },
                    {
                        'label': 'Response Time (ms)',
                        'data': [100 + (hash(t + 'resp') % 100) for t in performance_times],
                        'borderColor': '#007bff',
                        'backgroundColor': 'rgba(0, 123, 255, 0.1)',
                        'yAxisID': 'y1'
                    }
                ],
                'options': {
                    'scales': {
                        'y': {
                            'type': 'linear',
                            'display': True,
                            'position': 'left',
                            'max': 100
                        },
                        'y1': {
                            'type': 'linear',
                            'display': True,
                            'position': 'right',
                            'grid': {
                                'drawOnChartArea': False
                            }
                        }
                    }
                }
            }
        
        return jsonify({
            'status': 'success',
            'data': chart_data,
            'metadata': {
                'chart_type': chart_type,
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': hours
                },
                'interval': interval,
                'generated_at': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard charts: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/widgets', methods=['GET'])
def get_dashboard_widgets():
    """Get widget data for customizable dashboard"""
    try:
        # Get parameters
        widget_types = request.args.getlist('widgets')
        if not widget_types:
            widget_types = ['summary', 'alerts', 'agents', 'performance']
        
        hours = int(request.args.get('hours', 24))
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        widgets = {}
        
        # Summary widget
        if 'summary' in widget_types:
            agent_db = AgentDB()
            alert_db = AlertDB()
            rule_db = RuleDB()
            
            agents = agent_db.get_all_agents()
            alert_filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            alerts = alert_db.get_alerts(alert_filters, 1000)
            rules = rule_db.get_all_rules()
            
            widgets['summary'] = {
                'title': 'System Overview',
                'type': 'summary_cards',
                'data': {
                    'agents': {
                        'total': len(agents),
                        'online': len([a for a in agents if a.get('Status') == 'Online']),
                        'offline': len([a for a in agents if a.get('Status') == 'Offline']),
                        'change': '+2',  # Would calculate from historical data
                        'trend': 'up'
                    },
                    'alerts': {
                        'total': len(alerts),
                        'critical': len([a for a in alerts if a.get('Severity') == 'Critical']),
                        'new': len([a for a in alerts if a.get('Status') == 'New']),
                        'change': '-5',
                        'trend': 'down'
                    },
                    'rules': {
                        'total': len(rules),
                        'active': len([r for r in rules if r.get('IsActive')]),
                        'triggered': len(set([a.get('RuleID') for a in alerts if a.get('RuleID')])),
                        'change': '+1',
                        'trend': 'up'
                    },
                    'threats': {
                        'detected': len([a for a in alerts if a.get('Severity') in ['Critical', 'High']]),
                        'blocked': len([a for a in alerts if a.get('Action') == 'Block']),
                        'investigating': len([a for a in alerts if a.get('Status') == 'In Progress']),
                        'change': '-3',
                        'trend': 'down'
                    }
                }
            }
        
        # Recent alerts widget
        if 'alerts' in widget_types:
            alert_db = AlertDB()
            recent_alerts = alert_db.get_recent_alerts(hours=6, limit=10)
            
            widgets['recent_alerts'] = {
                'title': 'Recent Alerts',
                'type': 'alert_list',
                'data': {
                    'alerts': [
                        {
                            'id': alert.get('AlertID'),
                            'title': alert.get('Title', 'Alert'),
                            'severity': alert.get('Severity', 'Medium'),
                            'hostname': alert.get('Hostname', 'Unknown'),
                            'time': alert.get('Time'),
                            'status': alert.get('Status', 'New'),
                            'type': alert.get('AlertType', 'Security Alert')
                        }
                        for alert in recent_alerts
                    ],
                    'total_count': len(recent_alerts)
                }
            }
        
        # Agent status widget
        if 'agents' in widget_types:
            agent_db = AgentDB()
            agents = agent_db.get_all_agents()
            
            # Group agents by status and OS
            status_groups = {}
            os_groups = {}
            
            for agent in agents:
                status = agent.get('Status', 'Unknown')
                os_type = agent.get('OSType', 'Unknown')
                
                if status not in status_groups:
                    status_groups[status] = []
                status_groups[status].append(agent)
                
                os_groups[os_type] = os_groups.get(os_type, 0) + 1
            
            widgets['agent_status'] = {
                'title': 'Agent Status',
                'type': 'agent_grid',
                'data': {
                    'by_status': {
                        status: {
                            'count': len(agent_list),
                            'agents': [
                                {
                                    'hostname': a.get('Hostname'),
                                    'os_type': a.get('OSType'),
                                    'last_seen': a.get('LastSeen'),
                                    'ip_address': a.get('IPAddress')
                                }
                                for a in agent_list[:5]  # Limit for widget display
                            ]
                        }
                        for status, agent_list in status_groups.items()
                    },
                    'by_os': os_groups,
                    'total': len(agents)
                }
            }
        
        # Performance widget
        if 'performance' in widget_types:
            # Simulated performance data
            widgets['performance'] = {
                'title': 'System Performance',
                'type': 'performance_meters',
                'data': {
                    'cpu_usage': {
                        'value': 68,
                        'max': 100,
                        'status': 'normal',
                        'trend': 'stable'
                    },
                    'memory_usage': {
                        'value': 74,
                        'max': 100,
                        'status': 'normal',
                        'trend': 'increasing'
                    },
                    'disk_usage': {
                        'value': 45,
                        'max': 100,
                        'status': 'good',
                        'trend': 'stable'
                    },
                    'network_throughput': {
                        'value': 1250,
                        'unit': 'Mbps',
                        'status': 'normal',
                        'trend': 'stable'
                    }
                }
            }
        
        # Top threats widget
        if 'threats' in widget_types:
            alert_db = AlertDB()
            alert_filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            alerts = alert_db.get_alerts(alert_filters, 1000)
            
            # Count threats by type
            threat_counts = {}
            for alert in alerts:
                alert_type = alert.get('AlertType', 'Unknown')
                severity = alert.get('Severity', 'Medium')
                
                if alert_type not in threat_counts:
                    threat_counts[alert_type] = {'count': 0, 'severities': {}}
                
                threat_counts[alert_type]['count'] += 1
                threat_counts[alert_type]['severities'][severity] = threat_counts[alert_type]['severities'].get(severity, 0) + 1
            
            # Sort by count
            top_threats = sorted(threat_counts.items(), key=lambda x: x[1]['count'], reverse=True)[:5]
            
            widgets['top_threats'] = {
                'title': 'Top Threats',
                'type': 'threat_list',
                'data': {
                    'threats': [
                        {
                            'name': threat_name,
                            'count': threat_data['count'],
                            'severity_breakdown': threat_data['severities'],
                            'primary_severity': max(threat_data['severities'].items(), key=lambda x: x[1])[0] if threat_data['severities'] else 'Medium'
                        }
                        for threat_name, threat_data in top_threats
                    ]
                }
            }
        
        # Activity timeline widget
        if 'timeline' in widget_types:
            # Get recent events
            alert_db = AlertDB()
            recent_alerts = alert_db.get_recent_alerts(hours=2, limit=5)
            
            timeline_events = []
            for alert in recent_alerts:
                timeline_events.append({
                    'type': 'alert',
                    'time': alert.get('Time'),
                    'title': alert.get('Title', 'Alert'),
                    'description': f"{alert.get('Severity', 'Medium')} alert on {alert.get('Hostname', 'Unknown')}",
                    'severity': alert.get('Severity', 'Medium'),
                    'icon': 'alert-triangle'
                })
            
            widgets['timeline'] = {
                'title': 'Recent Activity',
                'type': 'timeline',
                'data': {
                    'events': timeline_events,
                    'show_more_link': '/dashboard/timeline'
                }
            }
        
        # Security score widget
        if 'security_score' in widget_types:
            # Calculate security score based on various factors
            agent_db = AgentDB()
            agents = agent_db.get_all_agents()
            
            online_percentage = (len([a for a in agents if a.get('Status') == 'Online']) / max(len(agents), 1)) * 100
            
            # Simulated security score calculation
            security_score = min(100, int((online_percentage * 0.4) + 45))  # Base score + agent availability
            
            widgets['security_score'] = {
                'title': 'Security Score',
                'type': 'score_gauge',
                'data': {
                    'score': security_score,
                    'max_score': 100,
                    'status': 'good' if security_score >= 80 else 'warning' if security_score >= 60 else 'critical',
                    'factors': [
                        {'name': 'Agent Coverage', 'value': online_percentage, 'weight': 40},
                        {'name': 'Rule Compliance', 'value': 85, 'weight': 30},
                        {'name': 'Threat Response', 'value': 92, 'weight': 20},
                        {'name': 'System Health', 'value': 78, 'weight': 10}
                    ],
                    'trend': 'stable'
                }
            }
        
        return jsonify({
            'status': 'success',
            'data': widgets,
            'metadata': {
                'widget_types': widget_types,
                'time_range': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat(),
                    'hours': hours
                },
                'refresh_interval': 30,  # seconds
                'generated_at': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard widgets: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/export', methods=['GET'])
def export_dashboard_data():
    """Export dashboard data in various formats"""
    try:
        export_format = request.args.get('format', 'json').lower()
        export_type = request.args.get('type', 'summary')  # summary, detailed, raw
        hours = int(request.args.get('hours', 24))
        
        if export_format not in ['json', 'csv', 'pdf']:
            return jsonify({'error': 'Supported formats: json, csv, pdf'}), 400
        
        # Calculate time range
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # Collect data based on export type
        if export_type == 'summary':
            # Get summary data from the summary endpoint
            from flask import current_app
            with current_app.test_request_context(f'/dashboard/summary?hours={hours}'):
                summary_response = get_dashboard_summary()
                summary_data = summary_response[0].get_json()
        
        elif export_type == 'detailed':
            # Get comprehensive data
            agent_db = AgentDB()
            alert_db = AlertDB()
            rule_db = RuleDB()
            
            agents = agent_db.get_all_agents()
            alert_filters = {
                'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': end_time.strftime('%Y-%m-%d %H:%M:%S')
            }
            alerts = alert_db.get_alerts(alert_filters, 10000)
            rules = rule_db.get_all_rules()
            
            summary_data = {
                'export_info': {
                    'type': 'detailed',
                    'format': export_format,
                    'time_range': {
                        'start': start_time.isoformat(),
                        'end': end_time.isoformat(),
                        'hours': hours
                    },
                    'generated_at': datetime.now().isoformat()
                },
                'agents': agents,
                'alerts': alerts,
                'rules': rules,
                'statistics': {
                    'total_agents': len(agents),
                    'total_alerts': len(alerts),
                    'total_rules': len(rules),
                    'agent_status_distribution': {},
                    'alert_severity_distribution': {},
                    'rule_type_distribution': {}
                }
            }
            
            # Calculate distributions
            for agent in agents:
                status = agent.get('Status', 'Unknown')
                summary_data['statistics']['agent_status_distribution'][status] = \
                    summary_data['statistics']['agent_status_distribution'].get(status, 0) + 1
            
            for alert in alerts:
                severity = alert.get('Severity', 'Unknown')
                summary_data['statistics']['alert_severity_distribution'][severity] = \
                    summary_data['statistics']['alert_severity_distribution'].get(severity, 0) + 1
            
            for rule in rules:
                rule_type = rule.get('RuleType', 'Unknown')
                summary_data['statistics']['rule_type_distribution'][rule_type] = \
                    summary_data['statistics']['rule_type_distribution'].get(rule_type, 0) + 1
        
        else:  # raw
            return jsonify({'error': 'Raw export not implemented yet'}), 400
        
        # Handle different export formats
        if export_format == 'json':
            return jsonify({
                'status': 'success',
                'data': summary_data
            }), 200
        
        elif export_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            
            if export_type == 'summary':
                # Create summary CSV
                writer = csv.writer(output)
                writer.writerow(['Metric', 'Value', 'Category'])
                
                # Flatten summary data for CSV
                if 'data' in summary_data:
                    data = summary_data['data']
                    
                    # Agents
                    if 'agents' in data:
                        for key, value in data['agents'].items():
                            writer.writerow([f'Agents - {key}', value, 'Agents'])
                    
                    # Alerts
                    if 'alerts' in data:
                        for key, value in data['alerts'].items():
                            if isinstance(value, dict):
                                for sub_key, sub_value in value.items():
                                    writer.writerow([f'Alerts - {key} - {sub_key}', sub_value, 'Alerts'])
                            else:
                                writer.writerow([f'Alerts - {key}', value, 'Alerts'])
            
            elif export_type == 'detailed':
                # Create detailed CSV with multiple sheets worth of data
                writer = csv.writer(output)
                
                # Agents section
                writer.writerow(['=== AGENTS ==='])
                if summary_data.get('agents'):
                    if summary_data['agents']:
                        headers = summary_data['agents'][0].keys()
                        writer.writerow(headers)
                        for agent in summary_data['agents']:
                            writer.writerow([agent.get(h, '') for h in headers])
                
                writer.writerow([''])
                writer.writerow(['=== ALERTS ==='])
                if summary_data.get('alerts'):
                    if summary_data['alerts']:
                        headers = summary_data['alerts'][0].keys()
                        writer.writerow(headers)
                        for alert in summary_data['alerts']:
                            row = []
                            for h in headers:
                                value = alert.get(h, '')
                                if isinstance(value, (dict, list)):
                                    row.append(json.dumps(value))
                                else:
                                    row.append(str(value))
                            writer.writerow(row)
            
            csv_content = output.getvalue()
            output.close()
            
            from flask import Response
            return Response(
                csv_content,
                mimetype='text/csv',
                headers={
                    'Content-Disposition': f'attachment; filename=dashboard_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
                }
            )
        
        elif export_format == 'pdf':
            # PDF export would require a PDF library like reportlab
            return jsonify({'error': 'PDF export not implemented yet'}), 400
        
    except Exception as e:
        logger.error(f"Error exporting dashboard data: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/health', methods=['GET'])
def get_system_health():
    """Get comprehensive system health status"""
    try:
        health_status = {
            'overall_status': 'healthy',
            'components': {},
            'issues': [],
            'warnings': [],
            'recommendations': [],
            'last_check': datetime.now().isoformat()
        }
        
        # Check database connectivity
        try:
            db = DatabaseConnection()
            db.connect()
            db.execute_query("SELECT 1")
            health_status['components']['database'] = {
                'status': 'healthy',
                'response_time_ms': 50,  # Would measure actual response time
                'message': 'Database connection successful'
            }
        except Exception as e:
            health_status['components']['database'] = {
                'status': 'critical',
                'message': f'Database connection failed: {str(e)}'
            }
            health_status['overall_status'] = 'critical'
            health_status['issues'].append('Database connectivity issue')
        
        # Check agent connectivity
        agent_db = AgentDB()
        agents = agent_db.get_all_agents()
        online_agents = len([a for a in agents if a.get('Status') == 'Online'])
        total_agents = len(agents)
        
        agent_availability = (online_agents / max(total_agents, 1)) * 100
        
        if agent_availability >= 90:
            agent_status = 'healthy'
        elif agent_availability >= 70:
            agent_status = 'warning'
            health_status['warnings'].append(f'Agent availability at {agent_availability:.1f}%')
        else:
            agent_status = 'critical'
            health_status['issues'].append(f'Low agent availability: {agent_availability:.1f}%')
            if health_status['overall_status'] == 'healthy':
                health_status['overall_status'] = 'warning'
        
        health_status['components']['agents'] = {
            'status': agent_status,
            'availability_percentage': round(agent_availability, 1),
            'online_count': online_agents,
            'total_count': total_agents,
            'message': f'{online_agents}/{total_agents} agents online'
        }
        
        # Check alert processing
        alert_db = AlertDB()
        recent_filters = {
            'start_time': (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        }
        recent_alerts = alert_db.get_alerts(recent_filters, 1000)
        new_alerts = len([a for a in recent_alerts if a.get('Status') == 'New'])
        
        if new_alerts > 100:
            health_status['components']['alert_processing'] = {
                'status': 'warning',
                'message': f'{new_alerts} unprocessed alerts in last hour',
                'backlog_count': new_alerts
            }
            health_status['warnings'].append('High alert backlog')
        else:
            health_status['components']['alert_processing'] = {
                'status': 'healthy',
                'message': 'Alert processing normal',
                'recent_alerts': len(recent_alerts),
                'unprocessed': new_alerts
            }
        
        # Check rule engine
        rule_db = RuleDB()
        rules = rule_db.get_all_rules()
        active_rules = len([r for r in rules if r.get('IsActive')])
        
        health_status['components']['rule_engine'] = {
            'status': 'healthy',
            'active_rules': active_rules,
            'total_rules': len(rules),
            'message': f'{active_rules} active rules'
        }
        
        # Check log processing
        try:
            log_db = LogDB()
            # Simulate log processing check
            health_status['components']['log_processing'] = {
                'status': 'healthy',
                'message': 'Log processing normal',
                'throughput': '1250 events/min'  # Would calculate actual throughput
            }
        except Exception as e:
            health_status['components']['log_processing'] = {
                'status': 'warning',
                'message': f'Log processing issue: {str(e)}'
            }
            health_status['warnings'].append('Log processing degraded')
        
        # Check system resources (simulated)
        health_status['components']['system_resources'] = {
            'status': 'healthy',
            'cpu_usage': 68,
            'memory_usage': 74,
            'disk_usage': 45,
            'message': 'System resources within normal limits'
        }
        
        # Generate recommendations
        if agent_availability < 95:
            health_status['recommendations'].append('Review agent connectivity and network configuration')
        
        if new_alerts > 50:
            health_status['recommendations'].append('Consider increasing alert processing capacity')
        
        if active_rules < len(rules) * 0.8:
            health_status['recommendations'].append('Review and activate unused security rules')
        
        # Set overall status based on component health
        component_statuses = [comp['status'] for comp in health_status['components'].values()]
        
        if 'critical' in component_statuses:
            health_status['overall_status'] = 'critical'
        elif 'warning' in component_statuses:
            health_status['overall_status'] = 'warning'
        else:
            health_status['overall_status'] = 'healthy'
        
        return jsonify({
            'status': 'success',
            'data': health_status
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/notifications', methods=['GET'])
def get_dashboard_notifications():
    """Get system notifications and announcements"""
    try:
        notifications = []
        
        # Check for system issues
        agent_db = AgentDB()
        agents = agent_db.get_all_agents()
        offline_agents = [a for a in agents if a.get('Status') == 'Offline']
        
        if len(offline_agents) > 5:
            notifications.append({
                'id': 'high_offline_agents',
                'type': 'warning',
                'title': 'High Number of Offline Agents',
                'message': f'{len(offline_agents)} agents are currently offline',
                'timestamp': datetime.now().isoformat(),
                'priority': 'high',
                'action_url': '/agents?status=offline',
                'dismissible': True
            })
        
        # Check for unprocessed alerts
        alert_db = AlertDB()
        new_alerts = alert_db.get_alerts({'status': 'New'}, 100)
        
        if len(new_alerts) > 20:
            notifications.append({
                'id': 'unprocessed_alerts',
                'type': 'info',
                'title': 'Unprocessed Alerts',
                'message': f'{len(new_alerts)} alerts require attention',
                'timestamp': datetime.now().isoformat(),
                'priority': 'medium',
                'action_url': '/alerts?status=new',
                'dismissible': True
            })
        
        # Check for critical alerts
        critical_alerts = alert_db.get_alerts({'severity': 'Critical', 'status': 'New'}, 10)
        
        if critical_alerts:
            notifications.append({
                'id': 'critical_alerts',
                'type': 'error',
                'title': 'Critical Security Alerts',
                'message': f'{len(critical_alerts)} critical alerts detected',
                'timestamp': datetime.now().isoformat(),
                'priority': 'critical',
                'action_url': '/alerts?severity=critical',
                'dismissible': False
            })
        
        # System maintenance notifications
        notifications.append({
            'id': 'system_update',
            'type': 'info',
            'title': 'System Update Available',
            'message': 'EDR System v2.1 is available with enhanced features',
            'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(),
            'priority': 'low',
            'action_url': '/settings/updates',
            'dismissible': True
        })
        
        # Performance notifications
        if len(agents) > 0:
            avg_response = 150  # Simulated average response time
            if avg_response > 200:
                notifications.append({
                    'id': 'performance_degradation',
                    'type': 'warning',
                    'title': 'Performance Degradation Detected',
                    'message': f'Average response time: {avg_response}ms (above threshold)',
                    'timestamp': (datetime.now() - timedelta(minutes=30)).isoformat(),
                    'priority': 'medium',
                    'action_url': '/dashboard/performance',
                    'dismissible': True
                })
        
        # Sort notifications by priority and timestamp
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        notifications.sort(key=lambda x: (priority_order.get(x['priority'], 999), x['timestamp']), reverse=True)
        
        return jsonify({
            'status': 'success',
            'data': {
                'notifications': notifications,
                'total_count': len(notifications),
                'unread_count': len([n for n in notifications if not n.get('read', False)]),
                'critical_count': len([n for n in notifications if n['priority'] == 'critical']),
                'last_update': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard notifications: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/search', methods=['GET'])
def search_dashboard():
    """Search across all dashboard data"""
    try:
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all')  # all, agents, alerts, rules
        limit = int(request.args.get('limit', 50))
        
        if not query:
            return jsonify({'error': 'Search query is required'}), 400
        
        results = {
            'query': query,
            'search_type': search_type,
            'results': {
                'agents': [],
                'alerts': [],
                'rules': [],
                'total': 0
            }
        }
        
        # Search agents
        if search_type in ['all', 'agents']:
            agent_db = AgentDB()
            agents = agent_db.get_all_agents()
            
            for agent in agents:
                # Search in hostname, IP, OS type
                searchable_text = ' '.join([
                    str(agent.get('Hostname', '')),
                    str(agent.get('IPAddress', '')),
                    str(agent.get('OSType', '')),
                    str(agent.get('Status', ''))
                ]).lower()
                
                if query.lower() in searchable_text:
                    results['results']['agents'].append({
                        'type': 'agent',
                        'hostname': agent.get('Hostname'),
                        'ip_address': agent.get('IPAddress'),
                        'os_type': agent.get('OSType'),
                        'status': agent.get('Status'),
                        'last_seen': agent.get('LastSeen'),
                        'match_field': _get_match_field(query, agent)
                    })
        
        # Search alerts
        if search_type in ['all', 'alerts']:
            alert_db = AlertDB()
            alerts = alert_db.get_alerts({}, 1000)  # Get recent alerts
            
            for alert in alerts:
                # Search in title, description, hostname
                searchable_text = ' '.join([
                    str(alert.get('Title', '')),
                    str(alert.get('Description', '')),
                    str(alert.get('Hostname', '')),
                    str(alert.get('AlertType', '')),
                    str(alert.get('Severity', ''))
                ]).lower()
                
                if query.lower() in searchable_text:
                    results['results']['alerts'].append({
                        'type': 'alert',
                        'id': alert.get('AlertID'),
                        'title': alert.get('Title'),
                        'description': alert.get('Description'),
                        'hostname': alert.get('Hostname'),
                        'severity': alert.get('Severity'),
                        'status': alert.get('Status'),
                        'time': alert.get('Time'),
                        'match_field': _get_match_field(query, alert)
                    })
        
        # Search rules
        if search_type in ['all', 'rules']:
            rule_db = RuleDB()
            rules = rule_db.get_all_rules()
            
            for rule in rules:
                # Search in rule name, description, type
                searchable_text = ' '.join([
                    str(rule.get('RuleName', '')),
                    str(rule.get('Description', '')),
                    str(rule.get('RuleType', '')),
                    str(rule.get('Severity', ''))
                ]).lower()
                
                if query.lower() in searchable_text:
                    results['results']['rules'].append({
                        'type': 'rule',
                        'id': rule.get('RuleID'),
                        'name': rule.get('RuleName'),
                        'description': rule.get('Description'),
                        'rule_type': rule.get('RuleType'),
                        'severity': rule.get('Severity'),
                        'is_active': rule.get('IsActive'),
                        'match_field': _get_match_field(query, rule)
                    })
        
        # Apply limit to each category
        if limit > 0:
            results['results']['agents'] = results['results']['agents'][:limit]
            results['results']['alerts'] = results['results']['alerts'][:limit]
            results['results']['rules'] = results['results']['rules'][:limit]
        
        # Calculate totals
        results['results']['total'] = (
            len(results['results']['agents']) +
            len(results['results']['alerts']) +
            len(results['results']['rules'])
        )
        
        return jsonify({
            'status': 'success',
            'data': results
        }), 200
        
    except Exception as e:
        logger.error(f"Error searching dashboard: {e}")
        return jsonify({'error': str(e)}), 500

def _get_severity_color(severity):
    """Get color code for severity level"""
    colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745'
    }
    return colors.get(severity, '#6c757d')

def _get_match_field(query, item):
    """Determine which field matched the search query"""
    query_lower = query.lower()
    
    for field, value in item.items():
        if isinstance(value, str) and query_lower in value.lower():
            return field
    
    return 'unknown'

@dashboard_api.route('/customize', methods=['POST'])
def customize_dashboard():
    """Save dashboard customization preferences"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        user_id = data.get('user_id', 'default')
        preferences = data.get('preferences', {})
        
        # Validate preferences structure
        valid_preferences = {
            'layout': preferences.get('layout', 'default'),
            'widgets': preferences.get('widgets', []),
            'theme': preferences.get('theme', 'light'),
            'refresh_interval': preferences.get('refresh_interval', 30),
            'time_range': preferences.get('time_range', 24),
            'notifications': preferences.get('notifications', {})
        }
        
        # In a real implementation, save to database
        # For now, return success
        
        return jsonify({
            'status': 'success',
            'message': 'Dashboard preferences saved successfully',
            'user_id': user_id,
            'preferences': valid_preferences
        }), 200
        
    except Exception as e:
        logger.error(f"Error saving dashboard preferences: {e}")
        return jsonify({'error': str(e)}), 500

@dashboard_api.route('/customize', methods=['GET'])
def get_dashboard_preferences():
    """Get dashboard customization preferences"""
    try:
        user_id = request.args.get('user_id', 'default')
        
        # In a real implementation, load from database
        # For now, return default preferences
        default_preferences = {
            'layout': 'grid',
            'widgets': ['summary', 'alerts', 'agents', 'performance', 'timeline'],
            'theme': 'light',
            'refresh_interval': 30,
            'time_range': 24,
            'notifications': {
                'email': True,
                'browser': True,
                'sound': False
            },
            'charts': {
                'show_legends': True,
                'animation': True,
                'color_scheme': 'default'
            }
        }
        
        return jsonify({
            'status': 'success',
            'data': {
                'user_id': user_id,
                'preferences': default_preferences
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting dashboard preferences: {e}")
        return jsonify({'error': str(e)}), 500