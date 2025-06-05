from .connection import DatabaseConnection
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

logger = logging.getLogger(__name__)

class RuleDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()

    def get_all_rules(self) -> List[Dict]:
        """Get all rules with dynamic field extraction"""
        try:
            query = """
                SELECT * FROM Rules
                ORDER BY CreatedAt DESC
            """
            cursor = self.db.execute_query(query)
            
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                rules = []
                for row in rows:
                    rule_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            rule_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        # Convert bit fields to boolean
                        elif col_name in ['IsActive', 'IsGlobal'] and isinstance(value, int):
                            rule_dict[col_name] = bool(value)
                        else:
                            rule_dict[col_name] = value
                    rules.append(rule_dict)
                
                return rules
            
            return []
            
        except Exception as e:
            logging.error(f"Error fetching all rules: {e}")
            return []

    def create_rule(self, rule_data: Dict) -> bool:
        """Create rule with dynamic field mapping"""
        try:
            if not rule_data:
                logging.error("Empty rule data received")
                return False
            
            # Normalize rule data
            normalized_data = self._normalize_rule_data(rule_data)
            if not normalized_data:
                logging.error("Failed to normalize rule data")
                return False
            
            # Validate rule data
            if not self._validate_rule_data(normalized_data):
                logging.error("Rule data validation failed")
                return False
            
            # Insert rule into database
            success = self.db.insert_data('Rules', normalized_data)
            
            if success:
                logging.info(f"Rule created: {normalized_data.get('RuleName', 'unknown')}")
            else:
                logging.error("Failed to insert rule into database")
                
            return success
            
        except Exception as e:
            logging.error(f"Error creating rule: {e}")
            return False

    def _normalize_rule_data(self, rule_data: Dict) -> Optional[Dict]:
        """Normalize rule data with dynamic field mapping"""
        try:
            # Get table schema
            schema = self.db.get_table_schema('Rules')
            if not schema:
                logging.error("No schema found for Rules table")
                return None
            
            available_columns = set(schema.get('columns', {}).keys())
            normalized = {}
            
            # Field mapping for various possible field names
            field_mappings = {
                'RuleName': ['RuleName', 'rule_name', 'name', 'title', 'rule_title'],
                'RuleType': ['RuleType', 'rule_type', 'type', 'category', 'rule_category'],
                'Description': ['Description', 'description', 'details', 'rule_description'],
                'Severity': ['Severity', 'severity', 'level', 'priority', 'risk_level'],
                'IsActive': ['IsActive', 'is_active', 'active', 'enabled'],
                'Action': ['Action', 'action', 'response', 'rule_action'],
                'IsGlobal': ['IsGlobal', 'is_global', 'global', 'applies_to_all'],
                'OSType': ['OSType', 'os_type', 'operating_system', 'platform', 'target_os']
            }
            
            # Map fields dynamically
            for db_field, possible_names in field_mappings.items():
                if db_field in available_columns:
                    value = self._extract_field_value(rule_data, possible_names)
                    if value is not None:
                        normalized[db_field] = self._convert_rule_field_value(db_field, value)
            
            # Set default values
            self._set_rule_defaults(normalized)
            
            return normalized
            
        except Exception as e:
            logging.error(f"Error normalizing rule data: {e}")
            return None

    def _extract_field_value(self, rule_data: Dict, possible_names: List[str]) -> Any:
        """Extract field value from rule data using possible field names"""
        for name in possible_names:
            if name in rule_data and rule_data[name] is not None:
                return rule_data[name]
        return None

    def _convert_rule_field_value(self, field_name: str, value: Any) -> Any:
        """Convert rule field value to appropriate type"""
        if value is None or value == '':
            return None
            
        field_lower = field_name.lower()
        
        try:
            # Boolean fields
            if any(keyword in field_lower for keyword in ['active', 'global', 'enabled']):
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.lower() in ['true', '1', 'yes', 'on', 'active', 'enabled']
                return bool(value)
            
            # Validate specific field values
            elif field_lower == 'severity':
                valid_severities = ['Low', 'Medium', 'High', 'Critical']
                str_value = str(value).strip()
                return str_value if str_value in valid_severities else 'Medium'
            
            elif field_lower == 'ruletype':
                valid_types = ['Process', 'File', 'Network']
                str_value = str(value).strip()
                return str_value if str_value in valid_types else 'Process'
            
            elif field_lower == 'action':
                valid_actions = ['Alert', 'AlertAndBlock', 'Block', 'Monitor']
                str_value = str(value).strip()
                return str_value if str_value in valid_actions else 'Alert'
            
            elif field_lower == 'ostype':
                valid_os = ['Windows', 'Linux', 'All']
                str_value = str(value).strip()
                return str_value if str_value in valid_os else 'All'
            
            # String fields - clean up
            else:
                str_value = str(value).strip()
                if str_value.upper() in ['NULL', 'NONE']:
                    return ''
                return str_value
                
        except (ValueError, TypeError) as e:
            logging.warning(f"Error converting rule value '{value}' for field '{field_name}': {e}")
            return str(value) if value else ''

    def _set_rule_defaults(self, normalized: Dict):
        """Set default values for rule fields"""
        defaults = {
            'IsActive': True,
            'IsGlobal': False,
            'Severity': 'Medium',
            'Action': 'Alert',
            'OSType': 'All'
        }
        
        for field, default_value in defaults.items():
            if field not in normalized or normalized[field] is None:
                normalized[field] = default_value

    def _validate_rule_data(self, rule_data: Dict) -> bool:
        """Validate rule data"""
        required_fields = ['RuleName', 'RuleType', 'Description', 'Severity']
        
        for field in required_fields:
            if field not in rule_data or not rule_data[field]:
                logging.error(f"Required rule field '{field}' is missing or empty")
                return False
        
        return True

    def update_rule(self, rule_id: int, rule_data: Dict) -> bool:
        """Update existing rule"""
        try:
            # Normalize rule data
            normalized_data = self._normalize_rule_data(rule_data)
            if not normalized_data:
                logging.error("Failed to normalize rule data for update")
                return False
            
            # Remove fields that shouldn't be updated
            update_data = {k: v for k, v in normalized_data.items() if k != 'RuleID'}
            
            # Add update timestamp
            update_data['UpdatedAt'] = 'GETDATE()'
            
            success = self.db.update_data('Rules', update_data, 'RuleID = ?', [rule_id])
            
            if success:
                logging.info(f"Rule {rule_id} updated successfully")
            
            return success
            
        except Exception as e:
            logging.error(f"Error updating rule {rule_id}: {e}")
            return False

    def delete_rule(self, rule_id: int) -> bool:
        """Delete rule by ID"""
        try:
            # First check if rule is referenced by alerts or agent rules
            references = self._check_rule_references(rule_id)
            if references:
                logging.warning(f"Rule {rule_id} has {references} references, marking as inactive instead of deleting")
                # Mark as inactive instead of deleting
                return self.db.update_data('Rules', {'IsActive': False}, 'RuleID = ?', [rule_id])
            
            # Safe to delete
            query = "DELETE FROM Rules WHERE RuleID = ?"
            cursor = self.db.execute_query(query, [rule_id])
            
            if cursor:
                rows_affected = cursor.rowcount
                if rows_affected > 0:
                    logging.info(f"Rule {rule_id} deleted successfully")
                    return True
            
            return False
            
        except Exception as e:
            logging.error(f"Error deleting rule {rule_id}: {e}")
            return False

    def _check_rule_references(self, rule_id: int) -> int:
        """Check how many references exist for this rule"""
        try:
            total_refs = 0
            
            # Check alerts
            cursor = self.db.execute_query("SELECT COUNT(*) FROM Alerts WHERE RuleID = ?", [rule_id])
            if cursor:
                total_refs += cursor.fetchone()[0]
            
            # Check agent rules
            cursor = self.db.execute_query("SELECT COUNT(*) FROM AgentRules WHERE RuleID = ?", [rule_id])
            if cursor:
                total_refs += cursor.fetchone()[0]
            
            return total_refs
            
        except Exception as e:
            logging.error(f"Error checking rule references for {rule_id}: {e}")
            return 0

    def get_rule_by_id(self, rule_id: int) -> Optional[Dict]:
        """Get specific rule by ID"""
        try:
            query = "SELECT * FROM Rules WHERE RuleID = ?"
            cursor = self.db.execute_query(query, [rule_id])
            
            if cursor:
                columns = [column[0] for column in cursor.description]
                row = cursor.fetchone()
                
                if row:
                    rule_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            rule_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        # Convert bit fields to boolean
                        elif col_name in ['IsActive', 'IsGlobal'] and isinstance(value, int):
                            rule_dict[col_name] = bool(value)
                        else:
                            rule_dict[col_name] = value
                    return rule_dict
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting rule {rule_id}: {e}")
            return None

    def get_rules_by_type(self, rule_type: str) -> List[Dict]:
        """Get rules by type"""
        try:
            query = "SELECT * FROM Rules WHERE RuleType = ? AND IsActive = 1 ORDER BY RuleName"
            cursor = self.db.execute_query(query, [rule_type])
            
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                rules = []
                for row in rows:
                    rule_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            rule_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        # Convert bit fields to boolean
                        elif col_name in ['IsActive', 'IsGlobal'] and isinstance(value, int):
                            rule_dict[col_name] = bool(value)
                        else:
                            rule_dict[col_name] = value
                    rules.append(rule_dict)
                
                return rules
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting rules by type {rule_type}: {e}")
            return []

    def get_agent_applicable_rules(self, hostname: str, os_type: str) -> List[Dict]:
        """Get rules applicable to a specific agent"""
        try:
            query = """
                SELECT r.* FROM Rules r
                WHERE r.IsActive = 1 
                AND (r.IsGlobal = 1 OR r.OSType = ? OR r.OSType = 'All')
                AND NOT EXISTS (
                    SELECT 1 FROM AgentRules ar 
                    WHERE ar.RuleID = r.RuleID AND ar.Hostname = ?
                )
                ORDER BY r.RuleType, r.Severity DESC, r.RuleName
            """
            cursor = self.db.execute_query(query, [os_type, hostname])
            
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                rules = []
                for row in rows:
                    rule_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            rule_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        # Convert bit fields to boolean
                        elif col_name in ['IsActive', 'IsGlobal'] and isinstance(value, int):
                            rule_dict[col_name] = bool(value)
                        else:
                            rule_dict[col_name] = value
                    rules.append(rule_dict)
                
                return rules
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting applicable rules for agent {hostname}: {e}")
            return []

    def get_rules_dashboard(self, filters: Dict = None) -> List[Dict]:
        """Get rules for dashboard with statistics"""
        try:
            query = """
                SELECT 
                    r.*,
                    COUNT(DISTINCT ar.Hostname) as AppliedAgents,
                    COUNT(DISTINCT a.AlertID) as TriggeredAlerts
                FROM Rules r
                LEFT JOIN AgentRules ar ON r.RuleID = ar.RuleID AND ar.IsActive = 1
                LEFT JOIN Alerts a ON r.RuleID = a.RuleID
            """
            params = []
            
            # Add WHERE clause if filters provided
            if filters:
                where_conditions = ['1=1']  # Always true condition to simplify AND logic
                
                if 'rule_type' in filters and filters['rule_type']:
                    where_conditions.append("r.RuleType = ?")
                    params.append(filters['rule_type'])
                
                if 'severity' in filters and filters['severity']:
                    where_conditions.append("r.Severity = ?")
                    params.append(filters['severity'])
                
                if 'is_active' in filters and filters['is_active'] is not None:
                    where_conditions.append("r.IsActive = ?")
                    params.append(1 if filters['is_active'] else 0)
                
                if 'action' in filters and filters['action']:
                    where_conditions.append("r.Action = ?")
                    params.append(filters['action'])
                
                query += " WHERE " + " AND ".join(where_conditions)
            
            query += """
                GROUP BY r.RuleID, r.RuleName, r.RuleType, r.Description, r.Severity,
                         r.IsActive, r.CreatedAt, r.UpdatedAt, r.Action, r.IsGlobal, r.OSType
                ORDER BY r.RuleType, r.Severity DESC, r.RuleName
            """
            
            cursor = self.db.execute_query(query, params)
            
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                rules = []
                for row in rows:
                    rule_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            rule_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        # Convert bit fields to boolean
                        elif col_name in ['IsActive', 'IsGlobal'] and isinstance(value, int):
                            rule_dict[col_name] = bool(value)
                        else:
                            rule_dict[col_name] = value
                    rules.append(rule_dict)
                
                return rules
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting rules dashboard: {e}")
            return []

    def check_rule_violation(self, rule_id: int, log_data: Dict) -> Optional[Dict]:
        """Check if log data violates a specific rule"""
        try:
            # Get rule information
            rule = self.get_rule_by_id(rule_id)
            if not rule or not rule.get('IsActive'):
                return None
            
            rule_type = rule.get('RuleType')
            severity = rule.get('Severity')
            action = rule.get('Action')
            
            # Check violation based on rule type
            if rule_type == 'Process':
                violation_data = self._check_process_rule_violation(rule_id, log_data)
            elif rule_type == 'File':
                violation_data = self._check_file_rule_violation(rule_id, log_data)
            elif rule_type == 'Network':
                violation_data = self._check_network_rule_violation(rule_id, log_data)
            else:
                return None
            
            if violation_data:
                return {
                    'rule_id': rule_id,
                    'rule_name': rule.get('RuleName'),
                    'severity': severity,
                    'action': action,
                    'description': rule.get('Description'),
                    'detection_data': json.dumps(log_data),
                    'violation_details': violation_data
                }
            
            return None
            
        except Exception as e:
            logging.error(f"Error checking rule violation for rule {rule_id}: {e}")
            return None

    def _check_process_rule_violation(self, rule_id: int, log_data: Dict) -> Optional[Dict]:
        """Check process rule violation"""
        try:
            # Get process rule conditions
            conditions_query = """
                SELECT ProcessName, ProcessPath
                FROM ProcessRuleConditions
                WHERE RuleID = ?
            """
            cursor = self.db.execute_query(conditions_query, [rule_id])
            
            conditions = []
            if cursor:
                conditions = cursor.fetchall()
            
            # If no specific conditions, use default suspicious process detection
            if not conditions:
                return self._check_default_process_rules(log_data)
            
            # Check each condition
            process_name = log_data.get('ProcessName', '').lower()
            executable_path = log_data.get('ExecutablePath', '').lower()
            
            for condition in conditions:
                condition_name = (condition.ProcessName or '').lower()
                condition_path = (condition.ProcessPath or '').lower()
                
                # Check process name match
                if condition_name and condition_name in process_name:
                    return {
                        'matched_condition': 'ProcessName',
                        'condition_value': condition.ProcessName,
                        'actual_value': log_data.get('ProcessName', ''),
                        'match_type': 'contains'
                    }
                
                # Check process path match
                if condition_path and condition_path in executable_path:
                    return {
                        'matched_condition': 'ProcessPath',
                        'condition_value': condition.ProcessPath,
                        'actual_value': log_data.get('ExecutablePath', ''),
                        'match_type': 'contains'
                    }
            
            return None
            
        except Exception as e:
            logging.error(f"Error checking process rule {rule_id}: {e}")
            return None

    def _check_file_rule_violation(self, rule_id: int, log_data: Dict) -> Optional[Dict]:
        """Check file rule violation"""
        try:
            # Get file rule conditions
            conditions_query = """
                SELECT FileName, FilePath
                FROM FileRuleConditions
                WHERE RuleID = ?
            """
            cursor = self.db.execute_query(conditions_query, [rule_id])
            
            conditions = []
            if cursor:
                conditions = cursor.fetchall()
            
            # If no specific conditions, use default file rules
            if not conditions:
                return self._check_default_file_rules(log_data)
            
            # Check each condition
            file_name = log_data.get('FileName', '').lower()
            file_path = log_data.get('FilePath', '').lower()
            
            for condition in conditions:
                condition_name = (condition.FileName or '').lower()
                condition_path = (condition.FilePath or '').lower()
                
                # Check file name match (support wildcards)
                if condition_name:
                    if self._match_pattern(file_name, condition_name):
                        return {
                            'matched_condition': 'FileName',
                            'condition_value': condition.FileName,
                            'actual_value': log_data.get('FileName', ''),
                            'match_type': 'pattern'
                        }
                
                # Check file path match
                if condition_path and condition_path in file_path:
                    return {
                        'matched_condition': 'FilePath',
                        'condition_value': condition.FilePath,
                        'actual_value': log_data.get('FilePath', ''),
                        'match_type': 'contains'
                    }
            
            return None
            
        except Exception as e:
            logging.error(f"Error checking file rule {rule_id}: {e}")
            return None

    def _check_network_rule_violation(self, rule_id: int, log_data: Dict) -> Optional[Dict]:
        """Check network rule violation"""
        try:
            # Get network rule conditions
            conditions_query = """
                SELECT IPAddress, Port, Protocol
                FROM NetworkRuleConditions
                WHERE RuleID = ?
            """
            cursor = self.db.execute_query(conditions_query, [rule_id])
            
            conditions = []
            if cursor:
                conditions = cursor.fetchall()
            
            # If no specific conditions, use default network rules
            if not conditions:
                return self._check_default_network_rules(log_data)
            
            # Check each condition
            local_address = log_data.get('LocalAddress', '')
            remote_address = log_data.get('RemoteAddress', '')
            local_port = log_data.get('LocalPort', 0)
            remote_port = log_data.get('RemotePort', 0)
            protocol = log_data.get('Protocol', '').upper()
            
            for condition in conditions:
                condition_ip = condition.IPAddress or ''
                condition_port = condition.Port or 0
                condition_protocol = (condition.Protocol or '').upper()
                
                # Check IP address match (support wildcards)
                if condition_ip:
                    if (self._match_ip_pattern(local_address, condition_ip) or 
                        self._match_ip_pattern(remote_address, condition_ip)):
                        return {
                            'matched_condition': 'IPAddress',
                            'condition_value': condition.IPAddress,
                            'actual_value': f"Local: {local_address}, Remote: {remote_address}",
                            'match_type': 'ip_pattern'
                        }
                
                # Check port match
                if condition_port and (condition_port == local_port or condition_port == remote_port):
                    return {
                        'matched_condition': 'Port',
                        'condition_value': condition.Port,
                        'actual_value': f"Local: {local_port}, Remote: {remote_port}",
                        'match_type': 'exact'
                    }
                
                # Check protocol match
                if condition_protocol and condition_protocol == protocol:
                    return {
                        'matched_condition': 'Protocol',
                        'condition_value': condition.Protocol,
                        'actual_value': protocol,
                        'match_type': 'exact'
                    }
            
            return None
            
        except Exception as e:
            logging.error(f"Error checking network rule {rule_id}: {e}")
            return None

    def _check_default_process_rules(self, log_data: Dict) -> Optional[Dict]:
        """Check default process rules when no specific conditions exist"""
        suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'wmic.exe', 'net.exe', 
            'reg.exe', 'schtasks.exe', 'at.exe', 'sc.exe'
        ]
        
        process_name = log_data.get('ProcessName', '').lower()
        
        for suspicious in suspicious_processes:
            if suspicious.lower() in process_name:
                return {
                    'matched_condition': 'DefaultSuspiciousProcess',
                    'condition_value': suspicious,
                    'actual_value': log_data.get('ProcessName', ''),
                    'match_type': 'suspicious_process'
                }
        
        return None

    def _check_default_file_rules(self, log_data: Dict) -> Optional[Dict]:
        """Check default file rules when no specific conditions exist"""
        sensitive_paths = ['system32', 'program files', 'windows']
        file_path = log_data.get('FilePath', '').lower()
        
        for sensitive in sensitive_paths:
            if sensitive in file_path:
                return {
                    'matched_condition': 'DefaultSensitivePath',
                    'condition_value': sensitive,
                    'actual_value': log_data.get('FilePath', ''),
                    'match_type': 'sensitive_path'
                }
        
        return None

    def _check_default_network_rules(self, log_data: Dict) -> Optional[Dict]:
        """Check default network rules when no specific conditions exist"""
        suspicious_ports = [22, 23, 3389, 445, 1433, 3306, 5432, 27017]
        remote_port = log_data.get('RemotePort', 0)
        
        if remote_port in suspicious_ports:
            return {
                'matched_condition': 'DefaultSuspiciousPort',
                'condition_value': remote_port,
                'actual_value': remote_port,
                'match_type': 'suspicious_port'
            }
        
        return None

    def _match_pattern(self, text: str, pattern: str) -> bool:
        """Match text against pattern with wildcard support"""
        try:
            import fnmatch
            return fnmatch.fnmatch(text, pattern)
        except Exception:
            return pattern in text

    def _match_ip_pattern(self, ip: str, pattern: str) -> bool:
        """Match IP address against pattern with wildcard support"""
        try:
            import fnmatch
            return fnmatch.fnmatch(ip, pattern)
        except Exception:
            return pattern in ip

    def create_cross_platform_rule(self, rule_data: Dict) -> bool:
        """Create a cross-platform rule with different conditions for Windows/Linux"""
        try:
            # First create the main rule
            if not self.create_rule(rule_data):
                return False
            
            # Get the created rule ID
            rule_name = rule_data.get('RuleName') or rule_data.get('rule_name')
            query = "SELECT TOP 1 RuleID FROM Rules WHERE RuleName = ? ORDER BY RuleID DESC"
            cursor = self.db.execute_query(query, [rule_name])
            
            if not cursor:
                logging.error("Failed to get created rule ID")
                return False
            
            row = cursor.fetchone()
            if not row:
                logging.error("No rule found after creation")
                return False
            
            rule_id = row[0]
            
            # Add Windows conditions if provided
            windows_conditions = rule_data.get('WindowsConditions') or rule_data.get('windows_conditions')
            if windows_conditions:
                self._add_rule_conditions(rule_id, windows_conditions, 'Windows')
            
            # Add Linux conditions if provided
            linux_conditions = rule_data.get('LinuxConditions') or rule_data.get('linux_conditions')
            if linux_conditions:
                self._add_rule_conditions(rule_id, linux_conditions, 'Linux')
            
            logging.info(f"Cross-platform rule created successfully: {rule_name}")
            return True
            
        except Exception as e:
            logging.error(f"Error creating cross-platform rule: {e}")
            return False

    def _add_rule_conditions(self, rule_id: int, conditions: List[Dict], os_type: str):
        """Add rule conditions for specific OS"""
        try:
            for condition in conditions:
                if 'ProcessName' in condition or 'ProcessPath' in condition:
                    condition_data = {
                        'RuleID': rule_id,
                        'ProcessName': condition.get('ProcessName'),
                        'ProcessPath': condition.get('ProcessPath')
                    }
                    self.db.insert_data('ProcessRuleConditions', condition_data)
                
                elif 'FileName' in condition or 'FilePath' in condition:
                    condition_data = {
                        'RuleID': rule_id,
                        'FileName': condition.get('FileName'),
                        'FilePath': condition.get('FilePath')
                    }
                    self.db.insert_data('FileRuleConditions', condition_data)
                
                elif 'IPAddress' in condition or 'Port' in condition or 'Protocol' in condition:
                    condition_data = {
                        'RuleID': rule_id,
                        'IPAddress': condition.get('IPAddress'),
                        'Port': condition.get('Port'),
                        'Protocol': condition.get('Protocol')
                    }
                    self.db.insert_data('NetworkRuleConditions', condition_data)
            
            logging.info(f"Added {len(conditions)} conditions for rule {rule_id} ({os_type})")
            
        except Exception as e:
            logging.error(f"Error adding rule conditions: {e}")