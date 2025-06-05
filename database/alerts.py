from .connection import DatabaseConnection
from datetime import datetime
import logging
import json
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class AlertDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()

    def create_alert(self, alert_data: Dict) -> bool:
        """Create alert with dynamic field mapping"""
        try:
            if not alert_data:
                logging.error("Empty alert data received")
                return False
            
            # Normalize alert data
            normalized_data = self._normalize_alert_data(alert_data)
            if not normalized_data:
                logging.error("Failed to normalize alert data")
                return False
            
            # Validate required fields
            if not self._validate_alert_data(normalized_data):
                logging.error("Alert data validation failed")
                return False
            
            # Insert alert into database
            success = self.db.insert_data('Alerts', normalized_data)
            
            if success:
                logging.info(f"Alert created for {normalized_data.get('Hostname', 'unknown')} - {normalized_data.get('Title', 'unknown')}")
            else:
                logging.error("Failed to insert alert into database")
                
            return success
            
        except Exception as e:
            logging.error(f"Error creating alert: {e}")
            return False

    def _normalize_alert_data(self, alert_data: Dict) -> Optional[Dict]:
        """Normalize alert data with dynamic field mapping"""
        try:
            # Get table schema
            schema = self.db.get_table_schema('Alerts')
            if not schema:
                logging.error("No schema found for Alerts table")
                return None
            
            available_columns = set(schema.get('columns', {}).keys())
            normalized = {}
            
            # Field mapping for various possible field names
            field_mappings = {
                'Time': ['Time', 'Timestamp', 'DateTime', 'timestamp', 'time', 'created_at', 'alert_time'],
                'Hostname': ['Hostname', 'hostname', 'host', 'computer_name', 'ComputerName', 'agent_name'],
                'RuleID': ['RuleID', 'rule_id', 'rule', 'rule_identifier', 'triggered_rule'],
                'AlertType': ['AlertType', 'alert_type', 'type', 'category', 'classification'],
                'Severity': ['Severity', 'severity', 'level', 'priority', 'risk_level'],
                'Status': ['Status', 'status', 'state', 'alert_status'],
                'Title': ['Title', 'title', 'name', 'alert_name', 'summary'],
                'Description': ['Description', 'description', 'details', 'message', 'alert_message'],
                'DetectionData': ['DetectionData', 'detection_data', 'data', 'context', 'raw_data', 'log_data'],
                'Action': ['Action', 'action', 'response', 'response_action', 'recommended_action']
            }
            
            # Map fields dynamically
            for db_field, possible_names in field_mappings.items():
                if db_field in available_columns:
                    value = self._extract_field_value(alert_data, possible_names)
                    if value is not None:
                        normalized[db_field] = self._convert_alert_field_value(db_field, value)
            
            # Set default values for required fields if missing
            self._set_alert_defaults(normalized)
            
            return normalized
            
        except Exception as e:
            logging.error(f"Error normalizing alert data: {e}")
            return None

    def _extract_field_value(self, alert_data: Dict, possible_names: List[str]) -> Any:
        """Extract field value from alert data using possible field names"""
        for name in possible_names:
            if name in alert_data and alert_data[name] is not None:
                return alert_data[name]
        return None

    def _convert_alert_field_value(self, field_name: str, value: Any) -> Any:
        """Convert alert field value to appropriate type"""
        if value is None or value == '':
            return None
            
        field_lower = field_name.lower()
        
        try:
            # Integer fields
            if 'id' in field_lower:
                return int(value) if value else 0
            
            # JSON fields
            elif 'data' in field_lower:
                if isinstance(value, (dict, list)):
                    return json.dumps(value, ensure_ascii=False)
                elif isinstance(value, str):
                    # Try to parse JSON to validate
                    try:
                        parsed = json.loads(value)
                        return value  # Already valid JSON string
                    except json.JSONDecodeError:
                        return json.dumps({'raw_data': value})
                else:
                    return json.dumps({'value': str(value)})
            
            # String fields - clean up
            else:
                str_value = str(value).strip()
                if str_value.upper() in ['NULL', 'NONE']:
                    return ''
                return str_value
                
        except (ValueError, TypeError) as e:
            logging.warning(f"Error converting alert value '{value}' for field '{field_name}': {e}")
            return str(value) if value else ''

    def _set_alert_defaults(self, normalized: Dict):
        """Set default values for alert fields"""
        defaults = {
            'Status': 'New',
            'Severity': 'Medium',
            'AlertType': 'Security Alert',
            'Title': 'EDR Alert',
            'Description': 'Security event detected',
            'DetectionData': '{}',
            'Action': 'Alert'
        }
        
        for field, default_value in defaults.items():
            if field not in normalized or normalized[field] is None:
                normalized[field] = default_value

    def _validate_alert_data(self, alert_data: Dict) -> bool:
        """Validate alert data"""
        required_fields = ['Hostname', 'RuleID', 'AlertType', 'Severity', 'Title', 'Description']
        
        for field in required_fields:
            if field not in alert_data or not alert_data[field]:
                logging.error(f"Required alert field '{field}' is missing or empty")
                return False
        
        # Validate RuleID exists
        if not self._validate_rule_id(alert_data['RuleID']):
            logging.error(f"Invalid RuleID: {alert_data['RuleID']}")
            return False
        
        return True

    def _validate_rule_id(self, rule_id: Any) -> bool:
        """Validate that rule ID exists in Rules table"""
        try:
            query = "SELECT 1 FROM Rules WHERE RuleID = ?"
            cursor = self.db.execute_query(query, [rule_id])
            return cursor and cursor.fetchone() is not None
        except Exception as e:
            logging.error(f"Error validating rule ID {rule_id}: {e}")
            return False

    def insert_alert(self, **kwargs) -> bool:
        """Insert alert with named parameters (legacy compatibility)"""
        try:
            # Convert named parameters to dictionary
            alert_data = {
                'hostname': kwargs.get('hostname'),
                'rule_id': kwargs.get('rule_id'),
                'alert_type': kwargs.get('alert_type'),
                'severity': kwargs.get('severity'),
                'status': kwargs.get('status', 'New'),
                'title': kwargs.get('title'),
                'description': kwargs.get('description'),
                'detection_data': kwargs.get('detection_data', ''),
                'action': kwargs.get('action', 'Alert')
            }
            
            return self.create_alert(alert_data)
            
        except Exception as e:
            logging.error(f"Error in insert_alert: {e}")
            return False

    def get_alerts(self, filters: Dict = None, limit: int = 100) -> List[Dict]:
        """Get alerts with dynamic filtering"""
        try:
            # Build base query
            query = f"""
                SELECT TOP {limit} 
                    a.*, r.RuleName, r.RuleType, ag.OSType
                FROM Alerts a
                LEFT JOIN Rules r ON a.RuleID = r.RuleID
                LEFT JOIN Agents ag ON a.Hostname = ag.Hostname
            """
            params = []
            
            # Add WHERE clause if filters provided
            if filters:
                where_conditions = []
                
                # Handle different filter types
                filter_mappings = {
                    'severity': 'a.Severity',
                    'status': 'a.Status',
                    'hostname': 'a.Hostname',
                    'alert_type': 'a.AlertType',
                    'rule_id': 'a.RuleID',
                    'from_date': 'a.Time >=',
                    'to_date': 'a.Time <=',
                    'start_time': 'a.Time >=',
                    'end_time': 'a.Time <='
                }
                
                for filter_key, filter_value in filters.items():
                    if filter_value is not None and filter_key in filter_mappings:
                        column_expr = filter_mappings[filter_key]
                        
                        if filter_key in ['from_date', 'to_date', 'start_time', 'end_time']:
                            where_conditions.append(f"{column_expr} ?")
                        else:
                            where_conditions.append(f"{column_expr} = ?")
                        
                        params.append(filter_value)
                
                if where_conditions:
                    query += " WHERE " + " AND ".join(where_conditions)
            
            query += " ORDER BY a.Time DESC"
            
            cursor = self.db.execute_query(query, params)
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                results = []
                for row in rows:
                    alert_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string for JSON serialization
                        if hasattr(value, 'strftime'):
                            alert_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            alert_dict[col_name] = value
                    results.append(alert_dict)
                
                return results
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting alerts: {e}")
            return []

    def update_alert_status(self, alert_id: int, status: str, action: str = None) -> bool:
        """Update alert status"""
        try:
            update_data = {'Status': status}
            
            if action:
                update_data['Action'] = action
            
            success = self.db.update_data('Alerts', update_data, 'AlertID = ?', [alert_id])
            
            if success:
                logging.info(f"Alert {alert_id} status updated to {status}")
            
            return success
            
        except Exception as e:
            logging.error(f"Error updating alert status for alert {alert_id}: {e}")
            return False

    def get_alert_stats(self, filters: Dict = None) -> Dict:
        """Get alert statistics"""
        try:
            base_query = """
                SELECT 
                    Severity,
                    COUNT(*) as AlertCount,
                    SUM(CASE WHEN Status = 'New' THEN 1 ELSE 0 END) as NewAlerts,
                    SUM(CASE WHEN Status = 'In Progress' THEN 1 ELSE 0 END) as InProgressAlerts,
                    SUM(CASE WHEN Status = 'Resolved' THEN 1 ELSE 0 END) as ResolvedAlerts
                FROM Alerts
            """
            params = []
            
            # Add WHERE clause if filters provided
            if filters:
                where_conditions = []
                
                if 'start_time' in filters and filters['start_time']:
                    where_conditions.append("Time >= ?")
                    params.append(filters['start_time'])
                
                if 'end_time' in filters and filters['end_time']:
                    where_conditions.append("Time <= ?")
                    params.append(filters['end_time'])
                
                if 'hostname' in filters and filters['hostname']:
                    where_conditions.append("Hostname = ?")
                    params.append(filters['hostname'])
                
                if where_conditions:
                    base_query += " WHERE " + " AND ".join(where_conditions)
            
            base_query += " GROUP BY Severity"
            
            cursor = self.db.execute_query(base_query, params)
            
            stats = {
                'total_alerts': 0,
                'by_severity': {},
                'by_status': {
                    'New': 0,
                    'In Progress': 0,
                    'Resolved': 0
                }
            }
            
            if cursor:
                for row in cursor.fetchall():
                    severity = row.Severity
                    alert_count = row.AlertCount
                    new_alerts = row.NewAlerts
                    in_progress_alerts = row.InProgressAlerts
                    resolved_alerts = row.ResolvedAlerts
                    
                    stats['by_severity'][severity] = alert_count
                    stats['total_alerts'] += alert_count
                    stats['by_status']['New'] += new_alerts
                    stats['by_status']['In Progress'] += in_progress_alerts
                    stats['by_status']['Resolved'] += resolved_alerts
            
            return stats
            
        except Exception as e:
            logging.error(f"Error getting alert stats: {e}")
            return {}

    def get_alerts_dashboard(self, **kwargs) -> List[Dict]:
        """Get alerts for dashboard (legacy compatibility)"""
        filters = {}
        
        # Map legacy parameter names
        if 'start_time' in kwargs:
            filters['start_time'] = kwargs['start_time']
        if 'end_time' in kwargs:
            filters['end_time'] = kwargs['end_time']
        if 'severity' in kwargs:
            filters['severity'] = kwargs['severity']
        if 'status' in kwargs:
            filters['status'] = kwargs['status']
        if 'hostname' in kwargs:
            filters['hostname'] = kwargs['hostname']
        
        return self.get_alerts(filters, kwargs.get('limit', 100))

    def cleanup_old_alerts(self, days: int = 30) -> int:
        """Clean up old resolved alerts"""
        try:
            query = """
                DELETE FROM Alerts 
                WHERE Status = 'Resolved' 
                AND Time < DATEADD(day, ?, GETDATE())
            """
            
            cursor = self.db.execute_query(query, [-days])
            if cursor:
                rows_deleted = cursor.rowcount
                logging.info(f"Deleted {rows_deleted} old resolved alerts")
                return rows_deleted
            
            return 0
            
        except Exception as e:
            logging.error(f"Error cleaning up old alerts: {e}")
            return 0

    def get_recent_alerts(self, hostname: str = None, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Get recent alerts for a specific timeframe"""
        try:
            filters = {
                'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Calculate start time
            from datetime import timedelta
            start_time = datetime.now() - timedelta(hours=hours)
            filters['start_time'] = start_time.strftime('%Y-%m-%d %H:%M:%S')
            
            if hostname:
                filters['hostname'] = hostname
            
            return self.get_alerts(filters, limit)
            
        except Exception as e:
            logging.error(f"Error getting recent alerts: {e}")
            return []

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict]:
        """Get specific alert by ID"""
        try:
            query = """
                SELECT a.*, r.RuleName, r.RuleType, ag.OSType
                FROM Alerts a
                LEFT JOIN Rules r ON a.RuleID = r.RuleID
                LEFT JOIN Agents ag ON a.Hostname = ag.Hostname
                WHERE a.AlertID = ?
            """
            
            cursor = self.db.execute_query(query, [alert_id])
            if cursor:
                columns = [column[0] for column in cursor.description]
                row = cursor.fetchone()
                
                if row:
                    alert_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            alert_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            alert_dict[col_name] = value
                    return alert_dict
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting alert {alert_id}: {e}")
            return None