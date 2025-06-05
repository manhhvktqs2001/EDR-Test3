import json
import logging
import threading
import time
import fnmatch
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from database.connection import DatabaseConnection

logger = logging.getLogger(__name__)

class RuleEngine:
    def __init__(self, refresh_interval=60):
        """Initialize RuleEngine with dynamic rule loading and checking"""
        self.db = None
        self.rules_cache = {}
        self.rule_conditions_cache = {}
        self.lock = threading.RLock()
        self.refresh_interval = refresh_interval
        self.is_initialized = False
        self.last_refresh = 0
        self._initialize()

    def _initialize(self):
        """Initialize RuleEngine"""
        try:
            self._initialize_database()
            self._load_all_rules()
            self.is_initialized = True
            
            # Start background refresh thread
            refresh_thread = threading.Thread(target=self._refresh_rules_loop, daemon=True)
            refresh_thread.start()
            
            logger.info("RuleEngine initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize RuleEngine: {e}")
            self.is_initialized = False

    def _initialize_database(self):
        """Initialize database connection"""
        try:
            self.db = DatabaseConnection()
            if not self.db.connect():
                raise Exception("Failed to connect to database")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise

    def _load_all_rules(self):
        """Load all active rules and their conditions"""
        try:
            with self.lock:
                if not self.db or not self.db.check_connection():
                    self._initialize_database()
                
                # Load rules
                rules_query = """
                    SELECT RuleID, RuleName, RuleType, Description, Severity, 
                           Action, IsActive, IsGlobal, OSType
                    FROM Rules
                    WHERE IsActive = 1
                """
                
                cursor = self.db.execute_query(rules_query)
                if not cursor:
                    logger.error("Failed to load rules from database")
                    return
                
                # Clear existing cache
                self.rules_cache.clear()
                self.rule_conditions_cache.clear()
                
                # Load rules into cache
                rules_count = 0
                for row in cursor.fetchall():
                    try:
                        rule_data = {
                            'RuleID': row.RuleID,
                            'RuleName': row.RuleName,
                            'RuleType': row.RuleType,
                            'Description': row.Description,
                            'Severity': row.Severity,
                            'Action': row.Action,
                            'IsActive': bool(row.IsActive),
                            'IsGlobal': bool(row.IsGlobal),
                            'OSType': row.OSType
                        }
                        
                        if self._validate_rule(rule_data):
                            self.rules_cache[row.RuleID] = rule_data
                            self._load_rule_conditions(row.RuleID, row.RuleType)
                            rules_count += 1
                        
                    except Exception as e:
                        logger.error(f"Error processing rule {row.RuleID}: {e}")
                        continue
                
                self.last_refresh = time.time()
                logger.info(f"Loaded {rules_count} rules into cache")
                
        except Exception as e:
            logger.error(f"Error loading rules: {e}")

    def _load_rule_conditions(self, rule_id: int, rule_type: str):
        """Load conditions for a specific rule"""
        try:
            conditions = {}
            
            if rule_type == 'Process':
                conditions = self._load_process_conditions(rule_id)
            elif rule_type == 'File':
                conditions = self._load_file_conditions(rule_id)
            elif rule_type == 'Network':
                conditions = self._load_network_conditions(rule_id)
            
            if conditions:
                self.rule_conditions_cache[rule_id] = conditions
                
        except Exception as e:
            logger.error(f"Error loading conditions for rule {rule_id}: {e}")

    def _load_process_conditions(self, rule_id: int) -> List[Dict]:
        """Load process rule conditions"""
        try:
            query = """
                SELECT ProcessName, ProcessPath
                FROM ProcessRuleConditions
                WHERE RuleID = ?
            """
            cursor = self.db.execute_query(query, [rule_id])
            
            conditions = []
            if cursor:
                for row in cursor.fetchall():
                    conditions.append({
                        'ProcessName': row.ProcessName,
                        'ProcessPath': row.ProcessPath
                    })
            
            return conditions
            
        except Exception as e:
            logger.error(f"Error loading process conditions for rule {rule_id}: {e}")
            return []

    def _load_file_conditions(self, rule_id: int) -> List[Dict]:
        """Load file rule conditions"""
        try:
            query = """
                SELECT FileName, FilePath
                FROM FileRuleConditions
                WHERE RuleID = ?
            """
            cursor = self.db.execute_query(query, [rule_id])
            
            conditions = []
            if cursor:
                for row in cursor.fetchall():
                    conditions.append({
                        'FileName': row.FileName,
                        'FilePath': row.FilePath
                    })
            
            return conditions
            
        except Exception as e:
            logger.error(f"Error loading file conditions for rule {rule_id}: {e}")
            return []

    def _load_network_conditions(self, rule_id: int) -> List[Dict]:
        """Load network rule conditions"""
        try:
            query = """
                SELECT IPAddress, Port, Protocol
                FROM NetworkRuleConditions
                WHERE RuleID = ?
            """
            cursor = self.db.execute_query(query, [rule_id])
            
            conditions = []
            if cursor:
                for row in cursor.fetchall():
                    conditions.append({
                        'IPAddress': row.IPAddress,
                        'Port': row.Port,
                        'Protocol': row.Protocol
                    })
            
            return conditions
            
        except Exception as e:
            logger.error(f"Error loading network conditions for rule {rule_id}: {e}")
            return []

    def _validate_rule(self, rule_data: Dict) -> bool:
        """Validate rule data"""
        try:
            required_fields = ['RuleID', 'RuleName', 'RuleType', 'Description', 'Severity', 'Action']
            for field in required_fields:
                if field not in rule_data or not rule_data[field]:
                    return False
            
            # Validate RuleType
            if rule_data['RuleType'] not in ['Process', 'File', 'Network']:
                return False
            
            # Validate Severity
            if rule_data['Severity'] not in ['Low', 'Medium', 'High', 'Critical']:
                return False
            
            # Validate Action
            if rule_data['Action'] not in ['Alert', 'AlertAndBlock', 'Block', 'Monitor']:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating rule: {e}")
            return False

    def _refresh_rules_loop(self):
        """Background thread to refresh rules periodically"""
        while True:
            try:
                time.sleep(self.refresh_interval)
                
                if not self.db or not self.db.check_connection():
                    self._initialize_database()
                
                self._load_all_rules()
                
            except Exception as e:
                logger.error(f"Error in rules refresh loop: {e}")

    def check_rules(self, log_type: str, log_data: Dict, hostname: str = None) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Optional[int], Optional[str]]:
        """Check log data against applicable rules"""
        try:
            if not self.is_initialized or not log_data:
                return False, None, None, None, None, None
            
            # Map log type to rule type
            rule_type = self._map_log_type_to_rule_type(log_type)
            if not rule_type:
                return False, None, None, None, None, None
            
            with self.lock:
                # Get applicable rules for this agent
                applicable_rules = self._get_applicable_rules(hostname, rule_type)
                
                # Check each rule
                for rule_id, rule_data in applicable_rules.items():
                    try:
                        if self._check_rule_violation(rule_id, rule_data, log_data):
                            return (
                                True,
                                rule_data['Description'],
                                json.dumps(log_data, default=str),
                                rule_data['Severity'],
                                rule_id,
                                rule_data['Action']
                            )
                    except Exception as e:
                        logger.error(f"Error checking rule {rule_id}: {e}")
                        continue
            
            return False, None, None, None, None, None
            
        except Exception as e:
            logger.error(f"Error checking rules: {e}")
            return False, None, None, None, None, None

    def _map_log_type_to_rule_type(self, log_type: str) -> Optional[str]:
        """Map log type to rule type"""
        mapping = {
            'PROCESS_LOGS': 'Process',
            'FILE_LOGS': 'File',
            'NETWORK_LOGS': 'Network'
        }
        return mapping.get(log_type.upper())

    def _get_applicable_rules(self, hostname: str, rule_type: str) -> Dict[int, Dict]:
        """Get rules applicable to the agent"""
        applicable_rules = {}
        
        try:
            # Get global rules
            for rule_id, rule_data in self.rules_cache.items():
                if (rule_data['RuleType'] == rule_type and 
                    rule_data['IsGlobal'] and 
                    rule_data['IsActive']):
                    applicable_rules[rule_id] = rule_data
            
            # Get agent-specific rules if hostname provided
            if hostname:
                agent_rules = self._get_agent_specific_rules(hostname, rule_type)
                applicable_rules.update(agent_rules)
            
            return applicable_rules
            
        except Exception as e:
            logger.error(f"Error getting applicable rules: {e}")
            return {}

    def _get_agent_specific_rules(self, hostname: str, rule_type: str) -> Dict[int, Dict]:
        """Get agent-specific rules"""
        try:
            query = """
                SELECT r.RuleID
                FROM Rules r
                JOIN AgentRules ar ON r.RuleID = ar.RuleID
                WHERE ar.Hostname = ? AND ar.IsActive = 1 
                AND r.IsActive = 1 AND r.RuleType = ?
            """
            
            cursor = self.db.execute_query(query, [hostname, rule_type])
            agent_rules = {}
            
            if cursor:
                for row in cursor.fetchall():
                    rule_id = row.RuleID
                    if rule_id in self.rules_cache:
                        agent_rules[rule_id] = self.rules_cache[rule_id]
            
            return agent_rules
            
        except Exception as e:
            logger.error(f"Error getting agent-specific rules for {hostname}: {e}")
            return {}

    def _check_rule_violation(self, rule_id: int, rule_data: Dict, log_data: Dict) -> bool:
        """Check if log violates a specific rule"""
        try:
            rule_type = rule_data['RuleType']
            
            if rule_type == 'Process':
                return self._check_process_violation(rule_id, log_data)
            elif rule_type == 'File':
                return self._check_file_violation(rule_id, log_data)
            elif rule_type == 'Network':
                return self._check_network_violation(rule_id, log_data)
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking rule violation for rule {rule_id}: {e}")
            return False

    def _check_process_violation(self, rule_id: int, log_data: Dict) -> bool:
        """Check process rule violation"""
        try:
            conditions = self.rule_conditions_cache.get(rule_id, [])
            
            # If no specific conditions, use default suspicious process detection
            if not conditions:
                return self._check_default_suspicious_processes(log_data)
            
            # Check each condition
            process_name = str(log_data.get('ProcessName', '')).lower()
            executable_path = str(log_data.get('ExecutablePath', '')).lower()
            
            for condition in conditions:
                condition_name = str(condition.get('ProcessName', '')).lower()
                condition_path = str(condition.get('ProcessPath', '')).lower()
                
                # Check process name match
                if condition_name and self._match_pattern(process_name, condition_name):
                    return True
                
                # Check process path match
                if condition_path and self._match_pattern(executable_path, condition_path):
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking process violation for rule {rule_id}: {e}")
            return False

    def _check_file_violation(self, rule_id: int, log_data: Dict) -> bool:
        """Check file rule violation"""
        try:
            conditions = self.rule_conditions_cache.get(rule_id, [])
            
            # If no specific conditions, use default file rules
            if not conditions:
                return self._check_default_suspicious_files(log_data)
            
            # Check each condition
            file_name = str(log_data.get('FileName', '')).lower()
            file_path = str(log_data.get('FilePath', '')).lower()
            
            for condition in conditions:
                condition_name = str(condition.get('FileName', '')).lower()
                condition_path = str(condition.get('FilePath', '')).lower()
                
                # Check file name match (support wildcards)
                if condition_name and self._match_pattern(file_name, condition_name):
                    return True
                
                # Check file path match
                if condition_path and condition_path in file_path:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking file violation for rule {rule_id}: {e}")
            return False

    def _check_network_violation(self, rule_id: int, log_data: Dict) -> bool:
        """Check network rule violation"""
        try:
            conditions = self.rule_conditions_cache.get(rule_id, [])
            
            # If no specific conditions, use default network rules
            if not conditions:
                return self._check_default_suspicious_network(log_data)
            
            # Check each condition
            local_address = str(log_data.get('LocalAddress', ''))
            remote_address = str(log_data.get('RemoteAddress', ''))
            local_port = int(log_data.get('LocalPort', 0))
            remote_port = int(log_data.get('RemotePort', 0))
            protocol = str(log_data.get('Protocol', '')).upper()
            
            for condition in conditions:
                condition_ip = str(condition.get('IPAddress', ''))
                condition_port = int(condition.get('Port', 0)) if condition.get('Port') else 0
                condition_protocol = str(condition.get('Protocol', '')).upper()
                
                # Check IP address match
                if condition_ip:
                    if (self._match_ip_pattern(local_address, condition_ip) or 
                        self._match_ip_pattern(remote_address, condition_ip)):
                        return True
                
                # Check port match
                if condition_port and (condition_port == local_port or condition_port == remote_port):
                    return True
                
                # Check protocol match
                if condition_protocol and condition_protocol == protocol:
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking network violation for rule {rule_id}: {e}")
            return False

    def _check_default_suspicious_processes(self, log_data: Dict) -> bool:
        """Check against default suspicious processes"""
        suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'wmic.exe', 'net.exe',
            'reg.exe', 'schtasks.exe', 'at.exe', 'sc.exe',
            'taskkill.exe', 'wevtutil.exe', 'vssadmin.exe',
            'bcdedit.exe', 'bootcfg.exe'
        ]
        
        process_name = str(log_data.get('ProcessName', '')).lower()
        command_line = str(log_data.get('CommandLine', '')).lower()
        
        # Check process name
        for suspicious in suspicious_processes:
            if suspicious.lower() in process_name:
                return True
        
        # Check for suspicious command line patterns
        suspicious_patterns = [
            'shadowcopy delete', 'vssadmin delete shadows',
            'wevtutil cl', 'reg delete', 'schtasks /create',
            'net user', 'net localgroup', 'whoami /priv'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in command_line:
                return True
        
        return False

    def _check_default_suspicious_files(self, log_data: Dict) -> bool:
        """Check against default suspicious file activities"""
        file_path = str(log_data.get('FilePath', '')).lower()
        file_name = str(log_data.get('FileName', '')).lower()
        event_type = str(log_data.get('EventType', '')).lower()
        
        # Check sensitive paths
        sensitive_paths = [
            'system32', 'program files', 'windows',
            'startup', 'appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup'
        ]
        
        for path in sensitive_paths:
            if path in file_path:
                return True
        
        # Check suspicious file extensions
        suspicious_extensions = [
            '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js',
            '.scr', '.pif', '.com'
        ]
        
        for ext in suspicious_extensions:
            if file_name.endswith(ext) and event_type in ['create', 'modify']:
                return True
        
        return False

    def _check_default_suspicious_network(self, log_data: Dict) -> bool:
        """Check against default suspicious network activities"""
        remote_port = int(log_data.get('RemotePort', 0))
        remote_address = str(log_data.get('RemoteAddress', ''))
        
        # Check suspicious ports
        suspicious_ports = [
            22, 23, 135, 139, 445, 1433, 1521, 3306, 3389,
            5432, 5900, 6379, 27017, 50070
        ]
        
        if remote_port in suspicious_ports:
            return True
        
        # Check for private IP ranges connecting outbound
        if self._is_private_ip(remote_address):
            return False  # Internal traffic is usually OK
        
        # Check for suspicious IP patterns (this could be enhanced with threat intel)
        suspicious_ip_patterns = [
            '10.0.0.*', '192.168.*.*', '172.16.*.*'
        ]
        
        for pattern in suspicious_ip_patterns:
            if self._match_ip_pattern(remote_address, pattern):
                return True
        
        return False

    def _match_pattern(self, text: str, pattern: str) -> bool:
        """Match text against pattern with wildcard support"""
        try:
            return fnmatch.fnmatch(text, pattern)
        except Exception:
            return pattern in text

    def _match_ip_pattern(self, ip: str, pattern: str) -> bool:
        """Match IP address against pattern"""
        try:
            return fnmatch.fnmatch(ip, pattern)
        except Exception:
            return pattern in ip

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is in private ranges"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except Exception:
            # Fallback to simple string matching
            private_ranges = ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.']
            return any(ip.startswith(range_start) for range_start in private_ranges)

    def get_rules_summary(self) -> Dict:
        """Get summary of loaded rules"""
        try:
            with self.lock:
                summary = {
                    'total_rules': len(self.rules_cache),
                    'by_type': {},
                    'by_severity': {},
                    'last_refresh': datetime.fromtimestamp(self.last_refresh).isoformat() if self.last_refresh else None
                }
                
                for rule_data in self.rules_cache.values():
                    rule_type = rule_data['RuleType']
                    severity = rule_data['Severity']
                    
                    summary['by_type'][rule_type] = summary['by_type'].get(rule_type, 0) + 1
                    summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
                
                return summary
                
        except Exception as e:
            logger.error(f"Error getting rules summary: {e}")
            return {}

    def refresh_rules(self) -> bool:
        """Manually refresh rules cache"""
        try:
            self._load_all_rules()
            return True
        except Exception as e:
            logger.error(f"Error refreshing rules: {e}")
            return False