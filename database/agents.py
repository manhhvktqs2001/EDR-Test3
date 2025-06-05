from .connection import DatabaseConnection
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class AgentDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()

    def register_agent(self, agent_data: Dict) -> bool:
        """Register or update agent with dynamic field mapping"""
        try:
            if not agent_data:
                logging.error("Empty agent data received")
                return False
            
            # Extract hostname for validation
            hostname = self._extract_hostname(agent_data)
            if not hostname or hostname in ['Unknown', 'Windows', 'Linux']:
                logging.error(f"Invalid hostname: {hostname}")
                return False
            
            # Normalize agent data
            normalized_data = self._normalize_agent_data(agent_data)
            if not normalized_data:
                logging.error("Failed to normalize agent data")
                return False
            
            # Check if agent already exists
            existing_agent = self.get_agent(hostname)
            
            if existing_agent:
                # Update existing agent
                success = self._update_agent(hostname, normalized_data)
                if success:
                    logging.info(f"Agent updated: {hostname}")
                else:
                    logging.error(f"Failed to update agent: {hostname}")
            else:
                # Register new agent
                success = self._register_new_agent(normalized_data)
                if success:
                    logging.info(f"New agent registered: {hostname}")
                    # Assign rules to new agent
                    self._assign_rules_to_agent(hostname, normalized_data.get('OSType', 'Unknown'))
                else:
                    logging.error(f"Failed to register new agent: {hostname}")
            
            return success
            
        except Exception as e:
            logging.error(f"Error registering agent: {e}")
            return False

    def _extract_hostname(self, agent_data: Dict) -> Optional[str]:
        """Extract hostname from various possible field names"""
        hostname_fields = ['Hostname', 'hostname', 'host', 'computer_name', 'ComputerName', 'name', 'Name']
        
        for field in hostname_fields:
            if field in agent_data and agent_data[field]:
                return str(agent_data[field]).strip()
        
        return None

    def _normalize_agent_data(self, agent_data: Dict) -> Optional[Dict]:
        """Normalize agent data with dynamic field mapping"""
        try:
            # Get table schema
            schema = self.db.get_table_schema('Agents')
            if not schema:
                logging.error("No schema found for Agents table")
                return None
            
            available_columns = set(schema.get('columns', {}).keys())
            normalized = {}
            
            # Field mapping for various possible field names
            field_mappings = {
                'Hostname': ['Hostname', 'hostname', 'host', 'computer_name', 'ComputerName', 'name'],
                'OSType': ['OSType', 'os_type', 'operating_system', 'os', 'platform', 'system'],
                'OSVersion': ['OSVersion', 'os_version', 'version', 'os_ver', 'operating_system_version'],
                'Architecture': ['Architecture', 'architecture', 'arch', 'platform_arch', 'processor_arch'],
                'IPAddress': ['IPAddress', 'ip_address', 'ip', 'local_ip', 'address'],
                'MACAddress': ['MACAddress', 'mac_address', 'mac', 'hardware_address', 'physical_address'],
                'AgentVersion': ['AgentVersion', 'agent_version', 'version', 'client_version', 'software_version'],
                'Status': ['Status', 'status', 'state', 'connection_status'],
                'IsActive': ['IsActive', 'is_active', 'active', 'enabled']
            }
            
            # Map fields dynamically
            for db_field, possible_names in field_mappings.items():
                if db_field in available_columns:
                    value = self._extract_field_value(agent_data, possible_names)
                    if value is not None:
                        normalized[db_field] = self._convert_agent_field_value(db_field, value)
            
            # Set default values for required fields if missing
            self._set_agent_defaults(normalized)
            
            # Validate required fields
            required_fields = ['Hostname', 'OSType']
            missing_fields = [field for field in required_fields if field not in normalized or not normalized[field]]
            
            if missing_fields:
                logging.error(f"Missing required agent fields: {missing_fields}")
                return None
            
            return normalized
            
        except Exception as e:
            logging.error(f"Error normalizing agent data: {e}")
            return None

    def _extract_field_value(self, agent_data: Dict, possible_names: List[str]) -> Any:
        """Extract field value from agent data using possible field names"""
        for name in possible_names:
            if name in agent_data and agent_data[name] is not None:
                return agent_data[name]
        return None

    def _convert_agent_field_value(self, field_name: str, value: Any) -> Any:
        """Convert agent field value to appropriate type"""
        if value is None or value == '':
            return None
            
        field_lower = field_name.lower()
        
        try:
            # Boolean fields
            if 'active' in field_lower or 'enabled' in field_lower:
                if isinstance(value, bool):
                    return value
                if isinstance(value, str):
                    return value.lower() in ['true', '1', 'yes', 'on', 'active']
                return bool(value)
            
            # String fields - clean up
            else:
                str_value = str(value).strip()
                if str_value.upper() in ['NULL', 'NONE']:
                    return ''
                return str_value
                
        except (ValueError, TypeError) as e:
            logging.warning(f"Error converting agent value '{value}' for field '{field_name}': {e}")
            return str(value) if value else ''

    def _set_agent_defaults(self, normalized: Dict):
        """Set default values for agent fields"""
        defaults = {
            'Status': 'Online',
            'IsActive': True,
            'Architecture': '',
            'IPAddress': '',
            'MACAddress': '',
            'AgentVersion': '1.0.0'
        }
        
        for field, default_value in defaults.items():
            if field not in normalized or normalized[field] is None:
                normalized[field] = default_value

    def _register_new_agent(self, agent_data: Dict) -> bool:
        """Register new agent in database"""
        try:
            success = self.db.insert_data('Agents', agent_data)
            return success
        except Exception as e:
            logging.error(f"Error registering new agent: {e}")
            return False

    def _update_agent(self, hostname: str, agent_data: Dict) -> bool:
        """Update existing agent"""
        try:
            # Remove hostname from update data to avoid conflicts
            update_data = {k: v for k, v in agent_data.items() if k != 'Hostname'}
            
            # Add update timestamp
            update_data['LastSeen'] = 'GETDATE()'
            update_data['LastHeartbeat'] = 'GETDATE()'
            
            success = self.db.update_data('Agents', update_data, 'Hostname = ?', [hostname])
            return success
        except Exception as e:
            logging.error(f"Error updating agent {hostname}: {e}")
            return False

    def _assign_rules_to_agent(self, hostname: str, os_type: str):
        """Assign rules to newly registered agent"""
        try:
            # Get global rules
            global_rules_query = """
                SELECT RuleID FROM Rules
                WHERE IsActive = 1 AND IsGlobal = 1
            """
            global_rules = self.db.execute_query(global_rules_query)
            
            # Get OS-specific rules
            os_rules_query = """
                SELECT RuleID FROM Rules
                WHERE IsActive = 1 AND IsGlobal = 0 AND OSType = ?
            """
            os_rules = self.db.execute_query(os_rules_query, [os_type])
            
            # Combine all applicable rules
            all_rules = []
            if global_rules:
                all_rules.extend([row[0] for row in global_rules.fetchall()])
            if os_rules:
                all_rules.extend([row[0] for row in os_rules.fetchall()])
            
            # Assign rules to agent
            assigned_count = 0
            for rule_id in all_rules:
                rule_assignment = {
                    'RuleID': rule_id,
                    'Hostname': hostname,
                    'IsActive': True
                }
                
                if self.db.insert_data('AgentRules', rule_assignment):
                    assigned_count += 1
            
            logging.info(f"Assigned {assigned_count} rules to agent {hostname}")
            
        except Exception as e:
            logging.error(f"Error assigning rules to agent {hostname}: {e}")

    def get_agent(self, hostname: str) -> Optional[Dict]:
        """Get agent information by hostname"""
        try:
            query = "SELECT * FROM Agents WHERE Hostname = ?"
            cursor = self.db.execute_query(query, [hostname])
            
            if cursor:
                columns = [column[0] for column in cursor.description]
                row = cursor.fetchone()
                
                if row:
                    agent_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            agent_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            agent_dict[col_name] = value
                    return agent_dict
            
            return None
            
        except Exception as e:
            logging.error(f"Error getting agent {hostname}: {e}")
            return None

    def get_all_agents(self) -> List[Dict]:
        """Get all active agents"""
        try:
            query = "SELECT * FROM Agents WHERE IsActive = 1 ORDER BY Hostname"
            cursor = self.db.execute_query(query)
            
            if cursor:
                columns = [column[0] for column in cursor.description]
                rows = cursor.fetchall()
                
                agents = []
                for row in rows:
                    agent_dict = {}
                    for i, value in enumerate(row):
                        col_name = columns[i]
                        # Convert datetime to string
                        if hasattr(value, 'strftime'):
                            agent_dict[col_name] = value.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            agent_dict[col_name] = value
                    agents.append(agent_dict)
                
                return agents
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting all agents: {e}")
            return []

    def update_agent_status(self, hostname: str, status: str) -> bool:
        """Update agent status"""
        try:
            update_data = {
                'Status': status,
                'LastSeen': 'GETDATE()'
            }
            
            success = self.db.update_data('Agents', update_data, 'Hostname = ?', [hostname])
            if success:
                logging.info(f"Agent status updated: {hostname} -> {status}")
            return success
            
        except Exception as e:
            logging.error(f"Error updating agent status for {hostname}: {e}")
            return False

    def update_heartbeat(self, hostname: str) -> bool:
        """Update agent heartbeat"""
        try:
            update_data = {
                'LastHeartbeat': 'GETDATE()',
                'LastSeen': 'GETDATE()',
                'Status': 'Online'
            }
            
            success = self.db.update_data('Agents', update_data, 'Hostname = ?', [hostname])
            return success
            
        except Exception as e:
            logging.error(f"Error updating heartbeat for {hostname}: {e}")
            return False

    def get_agent_rules(self, hostname: str) -> List[int]:
        """Get all rules assigned to an agent"""
        try:
            query = """
                SELECT r.RuleID 
                FROM Rules r
                JOIN AgentRules ar ON r.RuleID = ar.RuleID
                WHERE ar.Hostname = ? AND ar.IsActive = 1
            """
            cursor = self.db.execute_query(query, [hostname])
            
            if cursor:
                return [row[0] for row in cursor.fetchall()]
            
            return []
            
        except Exception as e:
            logging.error(f"Error getting agent rules for {hostname}: {e}")
            return []

    def assign_rule(self, hostname: str, rule_id: int) -> bool:
        """Assign a rule to an agent"""
        try:
            # Check if rule assignment already exists
            check_query = """
                SELECT 1 FROM AgentRules 
                WHERE RuleID = ? AND Hostname = ?
            """
            existing = self.db.execute_query(check_query, [rule_id, hostname])
            
            if existing and existing.fetchone():
                logging.info(f"Rule {rule_id} already assigned to agent {hostname}")
                return True
            
            # Insert new rule assignment
            rule_assignment = {
                'RuleID': rule_id,
                'Hostname': hostname,
                'IsActive': True
            }
            
            success = self.db.insert_data('AgentRules', rule_assignment)
            if success:
                logging.info(f"Rule {rule_id} assigned to agent {hostname}")
            
            return success
            
        except Exception as e:
            logging.error(f"Error assigning rule {rule_id} to agent {hostname}: {e}")
            return False

    def cleanup_offline_agents(self, offline_threshold_minutes: int = 5) -> int:
        """Mark agents as offline if they haven't sent heartbeat recently"""
        try:
            update_data = {'Status': 'Offline'}
            where_clause = f"Status != 'Offline' AND LastHeartbeat < DATEADD(minute, -{offline_threshold_minutes}, GETDATE())"
            
            success = self.db.update_data('Agents', update_data, where_clause)
            if success:
                # Get count of updated agents
                count_query = f"SELECT COUNT(*) FROM Agents WHERE {where_clause.replace('Status !=', 'Status =')}"
                cursor = self.db.execute_query(count_query)
                count = cursor.fetchone()[0] if cursor else 0
                
                if count > 0:
                    logging.info(f"Marked {count} agents as offline")
                return count
            
            return 0
            
        except Exception as e:
            logging.error(f"Error cleaning up offline agents: {e}")
            return 0