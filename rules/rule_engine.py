import json
import logging
import threading
import time
from database.connection import DatabaseConnection
import fnmatch

class RuleEngine:
    def __init__(self, refresh_interval=60):
        """Khởi tạo RuleEngine với khoảng thời gian làm mới quy tắc (giây)."""
        self.db = None
        self.rules_by_category = {
            'Process': [],
            'File': [],
            'Network': []
        }
        self.lock = threading.Lock()
        self.refresh_interval = refresh_interval
        self.is_initialized = False
        self._initialize()

    def _initialize(self):
        """Khởi tạo RuleEngine trong thread riêng."""
        try:
            self._initialize_database()
            self._load_rules()
            self.is_initialized = True
            # Start refresh thread
            refresh_thread = threading.Thread(target=self._refresh_rules_loop, daemon=True)
            refresh_thread.start()
        except Exception as e:
            logging.error(f"Failed to initialize RuleEngine: {e}")
            self.is_initialized = False

    def _initialize_database(self):
        """Khởi tạo kết nối database."""
        try:
            self.db = DatabaseConnection()
            if not self.db.connect():
                raise Exception("Failed to connect to database")
        except Exception as e:
            logging.error(f"Error initializing database: {e}")
            raise

    def _load_rules(self):
        """Tải và phân loại quy tắc từ database."""
        try:
            with self.lock:
                if not self.db or not self.db.check_connection():
                    if not self.db.connect():
                        return
                # Load rules with validation
                query = """
                SELECT r.RuleID, r.RuleName, r.RuleType, r.Description, r.Severity, r.Action,
                       r.IsActive, r.IsGlobal, r.CreatedAt, r.UpdatedAt
                FROM Rules r
                WHERE r.IsActive = 1
                AND EXISTS (
                    SELECT 1 FROM Rules r2 
                    WHERE r2.RuleID = r.RuleID 
                    AND r2.IsActive = 1
                )
                """
                try:
                    rules = self.db.execute_query(query)
                except Exception as e:
                    logging.error(f"Error loading rules: {e}")
                    return
                # Reset rules
                for category in self.rules_by_category:
                    self.rules_by_category[category] = []
                # Phân loại rules và validate
                total_loaded = 0
                for rule in rules:
                    try:
                        rule_type = rule[2]
                        if rule_type in self.rules_by_category:
                            rule_data = {
                                'RuleID': rule[0],
                                'RuleName': rule[1],
                                'RuleType': rule_type,
                                'Description': rule[3],
                                'Severity': rule[4],
                                'Action': rule[5],
                                'IsActive': rule[6],
                                'IsGlobal': rule[7],
                                'CreatedAt': rule[8],
                                'UpdatedAt': rule[9]
                            }
                            # Validate rule data
                            if self._validate_rule(rule_data):
                                self.rules_by_category[rule_type].append(rule_data)
                                total_loaded += 1
                            else:
                                logging.warning(f"Invalid rule data for RuleID {rule[0]}, skipping...")
                    except Exception as e:
                        logging.error(f"Error processing rule {rule[0]}: {e}")
                        continue
                # Log số lượng rule đã load
                for category in self.rules_by_category:
                    logging.info(f"Loaded {len(self.rules_by_category[category])} {category} rules from database.")
                logging.info(f"Total loaded rules from database: {total_loaded}")
        except Exception as e:
            logging.error(f"Error in _load_rules: {e}")

    def _validate_rule(self, rule_data):
        """Validate rule data"""
        try:
            required_fields = ['RuleID', 'RuleName', 'RuleType', 'Description', 'Severity', 'Action']
            for field in required_fields:
                if field not in rule_data or not rule_data[field]:
                    return False
            # Validate RuleType
            if rule_data['RuleType'] not in ['Process', 'File', 'Network']:
                return False
            # Validate Severity (bổ sung 'Critical')
            if rule_data['Severity'] not in ['Low', 'Medium', 'High', 'Critical']:
                return False
            # Validate Action (bổ sung 'AlertAndBlock')
            if rule_data['Action'] not in ['Alert', 'AlertAndBlock', 'Block', 'Monitor']:
                return False
            return True
        except Exception as e:
            logging.error(f"Error validating rule: {e}")
            return False

    def _refresh_rules_loop(self):
        """Làm mới quy tắc định kỳ."""
        while True:
            time.sleep(self.refresh_interval)
            try:
                if not self.db.check_connection():
                    self._initialize_database()
                self._load_rules()
            except Exception as e:
                logging.error(f"Failed to refresh rules: {e}")

    def check_rules(self, log_type, log_data, hostname=None):
        """Kiểm tra log với các quy tắc tương ứng, bao gồm rule chung và rule riêng của agent."""
        try:
            if not self.is_initialized or not log_data:
                return False, None, None, None, None, None

            category = self._map_log_type_to_category(log_type)
            if category not in ['Process', 'File', 'Network']:
                return False, None, None, None, None, None

            with self.lock:
                # 1. Lấy rule chung (IsGlobal=1)
                query_common = """
                    SELECT r.RuleID, r.RuleName, r.RuleType, r.Description, r.Severity, r.Action
                    FROM Rules r
                    WHERE r.IsActive = 1 AND r.IsGlobal = 1
                    AND EXISTS (
                        SELECT 1 FROM Rules r2 
                        WHERE r2.RuleID = r.RuleID 
                        AND r2.IsActive = 1
                    )
                """
                rules_common = self.db.execute_query(query_common)
                
                # 2. Lấy rule riêng của agent (nếu có hostname)
                rules_agent = []
                if hostname:
                    query_agent = """
                        SELECT r.RuleID, r.RuleName, r.RuleType, r.Description, r.Severity, r.Action
                        FROM Rules r
                        JOIN AgentRules ar ON r.RuleID = ar.RuleID
                        WHERE ar.Hostname = ? 
                        AND ar.IsActive = 1 
                        AND r.IsActive = 1
                        AND EXISTS (
                            SELECT 1 FROM Rules r2 
                            WHERE r2.RuleID = r.RuleID 
                            AND r2.IsActive = 1
                        )
                    """
                    rules_agent = self.db.execute_query(query_agent, (hostname,))
                
                # 3. Gộp rules và phân loại
                all_rules = [r for r in (rules_common or []) + (rules_agent or []) if r[2] == category]
                
                for rule in all_rules:
                    try:
                        rule_data = {
                            'RuleID': rule[0],
                            'RuleName': rule[1],
                            'RuleType': rule[2],
                            'Description': rule[3],
                            'Severity': rule[4],
                            'Action': rule[5]
                        }
                        
                        if self._validate_rule(rule_data) and self._check_rule_violation(rule_data, log_type, log_data):
                            return True, rule_data['Description'], json.dumps(log_data), rule_data['Severity'], rule_data['RuleID'], rule_data['Action']
                    except Exception as e:
                        logging.error(f"Error checking rule {rule[0]}: {e}")
                        continue
                        
            return False, None, None, None, None, None
        except Exception as e:
            logging.error(f"Error checking rules: {e}")
        return False, None, None, None, None, None

    def _check_rule_violation(self, rule, log_type, log_data):
        """Kiểm tra vi phạm rule cụ thể."""
        try:
            if log_type == "PROCESS_LOGS":
                process_name = log_data.get("ProcessName", "").lower()
                process_path = log_data.get("ExecutablePath", "").lower()
                return bool(process_name or process_path)
            elif log_type == "FILE_LOGS":
                file_name = log_data.get("FileName", "").lower()
                file_path = log_data.get("FilePath", "").lower()
                return bool(file_name or file_path)
            elif log_type == "NETWORK_LOGS":
                remote_ip = log_data.get("RemoteAddress", "")
                remote_port = log_data.get("RemotePort", 0)
                protocol = log_data.get("Protocol", "").upper()
                # Lấy điều kiện rule từ DB
                conditions = self._get_network_conditions(rule['RuleID'])
                for cond in conditions:
                    if (
                        self.match_ip(remote_ip, cond['IPAddress']) and
                        str(remote_port) == str(cond['Port']) and
                        protocol == (cond['Protocol'] or '').upper()
                    ):
                        return True
                return False
        except Exception as e:
            logging.error(f"Error in _check_rule_violation: {e}")
            return False
        return False

    def match_ip(self, ip, pattern):
        # pattern có thể là 10.10.10.* hoặc 192.168.*.*
        try:
            return fnmatch.fnmatch(ip, pattern)
        except Exception as e:
            logging.error(f"Error matching IP: {e}")
            return False

    def _get_network_conditions(self, rule_id):
        try:
            query = "SELECT IPAddress, Port, Protocol FROM NetworkRuleConditions WHERE RuleID = ?"
            rows = self.db.execute_query(query, (rule_id,))
            return [{'IPAddress': r[0], 'Port': r[1], 'Protocol': r[2]} for r in rows]
        except Exception as e:
            logging.error(f"Error getting network conditions for rule {rule_id}: {e}")
            return []

    def _map_log_type_to_category(self, log_type):
        """Ánh xạ log_type sang Category."""
        mapping = {
            "PROCESS_LOGS": "Process",
            "FILE_LOGS": "File",
            "NETWORK_LOGS": "Network"
        }
        return mapping.get(log_type, "Unknown") 

    def get_rules(self):
        """Lấy danh sách rules."""
        try:
            with self.lock:
                return self.rules_by_category
        except Exception as e:
            logging.error(f"Error getting rules: {e}")
            return {} 