import logging
from .connection import DatabaseConnection
import json
import sqlite3
from datetime import datetime

logger = logging.getLogger(__name__)

class RuleDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()

    def get_all_rules(self):
        try:
            query = """
                SELECT RuleID, RuleName, RuleType, Description, Severity, IsActive, CreatedAt, UpdatedAt, Action, IsGlobal, OSType
                FROM Rules
                ORDER BY CreatedAt DESC
            """
            rows = self.db.execute_query(query)
            rules = []
            if rows:
                for row in rows:
                    try:
                        rules.append({
                            "RuleID": row.RuleID,
                            "RuleName": row.RuleName,
                            "RuleType": row.RuleType,
                            "Description": row.Description,
                            "Severity": row.Severity,
                            "IsActive": bool(row.IsActive),
                            "CreatedAt": row.CreatedAt.strftime('%Y-%m-%d %H:%M:%S') if row.CreatedAt else None,
                            "UpdatedAt": row.UpdatedAt.strftime('%Y-%m-%d %H:%M:%S') if row.UpdatedAt else None,
                            "Action": row.Action,
                            "IsGlobal": bool(row.IsGlobal),
                            "OSType": row.OSType
                        })
                    except Exception as e:
                        logging.error(f"Error parsing rule: {e}")
            return rules
        except Exception as e:
            logging.error(f"Error fetching rules: {e}")
            return []

    def create_rule(self, data):
        try:
            query = """
                INSERT INTO Rules (RuleName, RuleType, Description, Severity, IsActive, CreatedAt, UpdatedAt, Action, IsGlobal, OSType)
                VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE(), ?, ?, ?)
            """
            params = (
                data.get("name"),
                data.get("type"),
                data.get("description"),
                data.get("severity"),
                1 if data.get("is_active") else 0,
                data.get("action"),
                1 if data.get("is_global") else 0,
                data.get("os_type") or 'All'
            )
            self.db.execute_query(query, params)
        except Exception as e:
            logging.error(f"Error creating rule: {e}")

    def update_rule(self, rule_id, data):
        try:
            query = """
                UPDATE Rules SET RuleName=?, RuleType=?, Description=?, Severity=?, IsActive=?, UpdatedAt=GETDATE(), Action=?, IsGlobal=?, OSType=?
                WHERE RuleID=?
            """
            params = (
                data.get("name"),
                data.get("type"),
                data.get("description"),
                data.get("severity"),
                1 if data.get("is_active") else 0,
                data.get("action"),
                1 if data.get("is_global") else 0,
                data.get("os_type") or 'All',
                rule_id
            )
            self.db.execute_query(query, params)
        except Exception as e:
            logging.error(f"Error updating rule: {e}")

    def delete_rule(self, rule_id):
        try:
            query = "DELETE FROM RULES WHERE [RuleID]=?"
            self.db.execute_query(query, (rule_id,))
        except Exception as e:
            logging.error(f"Error deleting rule: {e}")

    def get_rules_dashboard(self, rule_type=None, severity=None, is_active=None, action=None):
        """Get rules for dashboard."""
        try:
            # Use stored procedure if available
            params = (rule_type, severity, is_active, action)
            return self.db.execute_procedure('sp_GetRulesDashboard', params)
        except:
            # Fallback to direct query if procedure not available
            query = """
                SELECT 
                    r.RuleID, r.RuleName, r.RuleType, r.Severity,
                    r.IsActive, r.IsGlobal, r.CreatedAt, r.UpdatedAt,
                    r.Action,
                    COUNT(DISTINCT ar.Hostname) as AppliedAgents,
                    COUNT(DISTINCT a.AlertID) as TriggeredAlerts
                FROM Rules r
                LEFT JOIN AgentRules ar ON r.RuleID = ar.RuleID
                LEFT JOIN Alerts a ON r.RuleID = a.RuleID
                WHERE 
                    (? IS NULL OR r.RuleType = ?)
                    AND (? IS NULL OR r.Severity = ?)
                    AND (? IS NULL OR r.IsActive = ?)
                    AND (? IS NULL OR r.Action = ?)
                GROUP BY 
                    r.RuleID, r.RuleName, r.RuleType, r.Severity,
                    r.IsActive, r.IsGlobal, r.CreatedAt, r.UpdatedAt,
                    r.Action
                ORDER BY 
                    r.RuleType, r.Severity, r.RuleName
            """
            return self.db.execute_query(query, (
                rule_type, rule_type,
                severity, severity,
                is_active, is_active,
                action, action
            ))

    def create_cross_platform_rule(self, rule_data):
        """Create a cross-platform rule."""
        try:
            # Use stored procedure if available
            params = (
                rule_data['RuleName'],
                rule_data['RuleType'],
                rule_data['Description'],
                rule_data['Severity'],
                rule_data['Action'],
                rule_data.get('IsGlobal', False),
                rule_data.get('WindowsConditions'),
                rule_data.get('LinuxConditions')
            )
            return self.db.execute_procedure('sp_CreateCrossPlatformRule', params)
        except:
            # Fallback to direct query if procedure not available
            # First create the rule
            rule_result = self.create_rule(rule_data)
            if not rule_result:
                return False

            # Get the created rule ID
            query = "SELECT TOP 1 RuleID FROM Rules WHERE RuleName = ? ORDER BY RuleID DESC"
            result = self.db.execute_query(query, (rule_data['RuleName'],))
            if not result:
                return False

            rule_id = result[0][0]

            # Add Windows conditions if any
            if 'WindowsConditions' in rule_data:
                for condition in rule_data['WindowsConditions']:
                    data = {
                        'RuleID': rule_id,
                        'ProcessName': condition.get('ProcessName'),
                        'ProcessPath': condition.get('ProcessPath')
                    }
                    self.db.execute_insert('ProcessRuleConditions', data)

            # Add Linux conditions if any
            if 'LinuxConditions' in rule_data:
                for condition in rule_data['LinuxConditions']:
                    data = {
                        'RuleID': rule_id,
                        'ProcessName': condition.get('ProcessName'),
                        'ProcessPath': condition.get('ProcessPath')
                    }
                    self.db.execute_insert('ProcessRuleConditions', data)

            return True 

    def check_rule_violation(self, rule_id, log_data):
        """Kiểm tra vi phạm rule dựa trên log data"""
        try:
            # Lấy thông tin rule
            rule_query = """
            SELECT RuleType, Severity, Action, OSType
            FROM Rules
            WHERE RuleID = ? AND IsActive = 1
            """
            rule = self.db.execute_query(rule_query, (rule_id,))
            if not rule:
                return None

            rule = rule[0]
            rule_type = rule.RuleType
            severity = rule.Severity
            action = rule.Action
            os_type = rule.OSType

            # Kiểm tra điều kiện dựa trên loại rule
            if rule_type == 'Process':
                return self._check_process_rule(rule_id, log_data, severity, action)
            elif rule_type == 'File':
                return self._check_file_rule(rule_id, log_data, severity, action)
            elif rule_type == 'Network':
                return self._check_network_rule(rule_id, log_data, severity, action)
            
            return None
        except Exception as e:
            logging.error(f"Error checking rule violation: {e}")
            return None

    def _check_process_rule(self, rule_id, log_data, severity, action):
        """Kiểm tra vi phạm rule process"""
        try:
            # Lấy điều kiện của rule
            conditions_query = """
            SELECT ProcessName, ProcessPath
            FROM ProcessRuleConditions
            WHERE RuleID = ?
            """
            conditions = self.db.execute_query(conditions_query, (rule_id,))
            
            if not conditions:
                return None

            # Kiểm tra từng điều kiện
            for condition in conditions:
                process_name = condition.ProcessName
                process_path = condition.ProcessPath

                # Kiểm tra tên process
                if process_name and process_name.lower() in log_data.get('ProcessName', '').lower():
                    return {
                        'severity': severity,
                        'action': action,
                        'detection_data': json.dumps(log_data)
                    }

                # Kiểm tra đường dẫn process
                if process_path and process_path.lower() in log_data.get('ExecutablePath', '').lower():
                    return {
                        'severity': severity,
                        'action': action,
                        'detection_data': json.dumps(log_data)
                    }

            return None
        except Exception as e:
            logging.error(f"Error checking process rule: {e}")
            return None

    def _check_file_rule(self, rule_id, log_data, severity, action):
        """Kiểm tra vi phạm rule file"""
        try:
            # Lấy điều kiện của rule
            conditions_query = """
            SELECT FileName, FilePath
            FROM FileRuleConditions
            WHERE RuleID = ?
            """
            conditions = self.db.execute_query(conditions_query, (rule_id,))
            
            if not conditions:
                return None

            # Kiểm tra từng điều kiện
            for condition in conditions:
                file_name = condition.FileName
                file_path = condition.FilePath

                # Kiểm tra tên file
                if file_name and file_name.lower() in log_data.get('FileName', '').lower():
                    return {
                        'severity': severity,
                        'action': action,
                        'detection_data': json.dumps(log_data)
                    }

                # Kiểm tra đường dẫn file
                if file_path and file_path.lower() in log_data.get('FilePath', '').lower():
                    return {
                        'severity': severity,
                        'action': action,
                        'detection_data': json.dumps(log_data)
                    }

            return None
        except Exception as e:
            logging.error(f"Error checking file rule: {e}")
            return None

    def _check_network_rule(self, rule_id, log_data, severity, action):
        """Kiểm tra vi phạm rule network"""
        try:
            # Lấy điều kiện của rule
            conditions_query = """
            SELECT IPAddress, Port, Protocol
            FROM NetworkRuleConditions
            WHERE RuleID = ?
            """
            conditions = self.db.execute_query(conditions_query, (rule_id,))
            
            if not conditions:
                return None

            # Kiểm tra từng điều kiện
            for condition in conditions:
                ip_address = condition.IPAddress
                port = condition.Port
                protocol = condition.Protocol

                # Kiểm tra IP
                if ip_address and ip_address in [log_data.get('LocalAddress', ''), log_data.get('RemoteAddress', '')]:
                    return {
                        'severity': severity,
                        'action': action,
                        'detection_data': json.dumps(log_data)
                    }

                # Kiểm tra port
                if port and port in [log_data.get('LocalPort', 0), log_data.get('RemotePort', 0)]:
                    return {
                        'severity': severity,
                        'action': action,
                        'detection_data': json.dumps(log_data)
                    }

                # Kiểm tra protocol
                if protocol and protocol.lower() == log_data.get('Protocol', '').lower():
                    return {
                        'severity': severity,
                        'action': action,
                        'detection_data': json.dumps(log_data)
                    }

            return None
        except Exception as e:
            logging.error(f"Error checking network rule: {e}")
            return None

def get_db_connection():
    """Tạo kết nối đến database"""
    try:
        conn = sqlite3.connect('edr.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
        return None

def get_rules(rule_type=None):
    """Lấy danh sách rules từ database
    
    Args:
        rule_type (str, optional): Loại rule cần lấy ('process', 'file', 'network'). 
                                 Nếu None thì lấy tất cả.
    
    Returns:
        list: Danh sách rules
    """
    try:
        conn = get_db_connection()
        if not conn:
            return []
            
        cursor = conn.cursor()
        
        if rule_type:
            cursor.execute("""
                SELECT * FROM rules 
                WHERE RuleType = ? AND Enabled = 1
                ORDER BY RuleID
            """, (rule_type,))
        else:
            cursor.execute("""
                SELECT * FROM rules 
                WHERE Enabled = 1
                ORDER BY RuleID
            """)
            
        rules = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        logger.info(f"Loaded {len(rules)} rules from database")
        return rules
        
    except Exception as e:
        logger.error(f"Error getting rules: {e}")
        return []

def create_rule(rule_data):
    """Tạo rule mới
    
    Args:
        rule_data (dict): Thông tin rule cần tạo
        
    Returns:
        bool: True nếu tạo thành công, False nếu thất bại
    """
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO rules (
                RuleName, RuleType, RuleDescription, 
                RuleCondition, Severity, Enabled,
                CreatedAt, UpdatedAt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule_data.get('name'),
            rule_data.get('type'),
            rule_data.get('description'),
            rule_data.get('condition'),
            rule_data.get('severity', 'Medium'),
            rule_data.get('enabled', 1),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created new rule: {rule_data.get('name')}")
        return True
        
    except Exception as e:
        logger.error(f"Error creating rule: {e}")
        return False

def update_rule(rule_id, rule_data):
    """Cập nhật rule
    
    Args:
        rule_id (int): ID của rule cần cập nhật
        rule_data (dict): Thông tin rule cần cập nhật
        
    Returns:
        bool: True nếu cập nhật thành công, False nếu thất bại
    """
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE rules SET
                RuleName = ?,
                RuleType = ?,
                RuleDescription = ?,
                RuleCondition = ?,
                Severity = ?,
                Enabled = ?,
                UpdatedAt = ?
            WHERE RuleID = ?
        """, (
            rule_data.get('name'),
            rule_data.get('type'),
            rule_data.get('description'),
            rule_data.get('condition'),
            rule_data.get('severity'),
            rule_data.get('enabled', 1),
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            rule_id
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Updated rule ID {rule_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error updating rule: {e}")
        return False

def delete_rule(rule_id):
    """Xóa rule
    
    Args:
        rule_id (int): ID của rule cần xóa
        
    Returns:
        bool: True nếu xóa thành công, False nếu thất bại
    """
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        cursor.execute("DELETE FROM rules WHERE RuleID = ?", (rule_id,))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Deleted rule ID {rule_id}")
        return True
        
    except Exception as e:
        logger.error(f"Error deleting rule: {e}")
        return False

def get_rule_by_id(rule_id):
    """Lấy thông tin rule theo ID
    
    Args:
        rule_id (int): ID của rule cần lấy
        
    Returns:
        dict: Thông tin rule hoặc None nếu không tìm thấy
    """
    try:
        conn = get_db_connection()
        if not conn:
            return None
            
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules WHERE RuleID = ?", (rule_id,))
        
        rule = cursor.fetchone()
        conn.close()
        
        if rule:
            return dict(rule)
        return None
        
    except Exception as e:
        logger.error(f"Error getting rule by ID: {e}")
        return None 