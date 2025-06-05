from .connection import DatabaseConnection
from datetime import datetime, timedelta
import logging
import sqlite3

logger = logging.getLogger('EDR_Server')

class AgentDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()

    def register_or_update(self, hostname, os_type, os_version, arch, ip, mac, agent_version):
        """Đăng ký mới hoặc cập nhật agent theo hostname."""
        try:
            # Nếu agent đã tồn tại thì update, chưa có thì insert
            query = """
            IF EXISTS (SELECT 1 FROM Agents WHERE Hostname = ?)
                UPDATE Agents SET OSType=?, OSVersion=?, Architecture=?, IPAddress=?, MACAddress=?, AgentVersion=?, Status='Online', IsActive=1, LastHeartbeat=GETDATE(), LastSeen=GETDATE() WHERE Hostname=?
            ELSE
                INSERT INTO Agents (Hostname, OSType, OSVersion, Architecture, IPAddress, MACAddress, AgentVersion, Status, IsActive, FirstSeen, LastHeartbeat, LastSeen)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Online', 1, GETDATE(), GETDATE(), GETDATE())
            """
            self.db.execute_query(query, (
                hostname, os_type, os_version, arch, ip, mac, agent_version, hostname,  # update params
                hostname, os_type, os_version, arch, ip, mac, agent_version            # insert params
            ))
            logging.info(f"SUCCESS: Agent updated - {hostname}")
            return True
        except Exception as e:
            logging.error(f"ERROR: Failed to update agent - {e}")
            return False

    def update_status(self, hostname, status):
        """Cập nhật trạng thái agent."""
        try:
            query = "UPDATE Agents SET Status=?, LastSeen=GETDATE() WHERE Hostname=?"
            self.db.execute_query(query, (status, hostname))
            logging.info(f"SUCCESS: Agent status updated - {hostname} ({status})")
            return True
        except Exception as e:
            logging.error(f"ERROR: Failed to update agent status - {e}")
            return False

    def update_heartbeat(self, hostname):
        """Cập nhật thời gian heartbeat cho agent."""
        try:
            query = "UPDATE Agents SET LastHeartbeat = GETDATE(), LastSeen = GETDATE(), Status = 'Online' WHERE Hostname = ?"
            self.db.execute_query(query, (hostname,))
            logging.info(f"SUCCESS: Agent heartbeat updated - {hostname}")
            return True
        except Exception as e:
            logging.error(f"ERROR: Failed to update agent heartbeat - {e}")
            return False

    def get_all_agents(self):
        """Lấy danh sách tất cả agent."""
        try:
            query = "SELECT AgentID, Hostname, OSType, OSVersion, Architecture, IPAddress, MACAddress, AgentVersion, Status, LastHeartbeat, LastSeen FROM Agents WHERE IsActive=1"
            rows = self.db.execute_query(query)
            agents = []
            if rows:
                for row in rows:
                    agents.append({
                        "agent_id": row.AgentID,
                        "hostname": row.Hostname,
                        "os_type": row.OSType,
                        "os_version": row.OSVersion,
                        "architecture": row.Architecture,
                        "ip_address": row.IPAddress,
                        "mac_address": row.MACAddress,
                        "agent_version": row.AgentVersion,
                        "status": row.Status,
                        "last_heartbeat": row.LastHeartbeat.strftime('%Y-%m-%d %H:%M:%S') if row.LastHeartbeat else None,
                        "last_seen": row.LastSeen.strftime('%Y-%m-%d %H:%M:%S') if row.LastSeen else None
                    })
            return agents
        except Exception as e:
            logging.error(f"Error getting agents: {e}")
            return []

    def get_agent(self, hostname):
        """Lấy thông tin chi tiết agent theo hostname."""
        try:
            query = "SELECT AgentID, Hostname, OSType, OSVersion, Architecture, IPAddress, MACAddress, AgentVersion, Status, LastHeartbeat, LastSeen FROM Agents WHERE Hostname=?"
            rows = self.db.execute_query(query, (hostname,))
            if rows and len(rows) > 0:
                row = rows[0]
                return {
                    "agent_id": row.AgentID,
                    "hostname": row.Hostname,
                    "os_type": row.OSType,
                    "os_version": row.OSVersion,
                    "architecture": row.Architecture,
                    "ip_address": row.IPAddress,
                    "mac_address": row.MACAddress,
                    "agent_version": row.AgentVersion,
                    "status": row.Status,
                    "last_heartbeat": row.LastHeartbeat.strftime('%Y-%m-%d %H:%M:%S') if row.LastHeartbeat else None,
                    "last_seen": row.LastSeen.strftime('%Y-%m-%d %H:%M:%S') if row.LastSeen else None
                }
            return None
        except Exception as e:
            logging.error(f"Error getting agent {hostname}: {e}")
            return None

    def register_agent(self, agent_data):
        """Register a new agent or update existing one, then assign rules."""
        try:
            # Nếu hostname không hợp lệ thì bỏ qua
            if not agent_data.get('Hostname') or agent_data.get('Hostname') in ['Unknown', 'Windows']:
                logging.error(f"Skip register agent with invalid hostname: {agent_data}")
                return False

            # Nếu agent đã tồn tại thì bỏ qua
            if self.get_agent(agent_data.get('Hostname')):
                logging.info(f"Agent {agent_data.get('Hostname')} already exists. Skip register and rule assignment.")
                return True

            # Chuẩn bị params với giá trị mặc định là chuỗi rỗng nếu None
            params = [
                agent_data.get('Hostname'),
                agent_data.get('OSType'),
                agent_data.get('OSVersion'),
                agent_data.get('Architecture') or "",
                agent_data.get('IPAddress') or "",
                agent_data.get('MACAddress') or "",
                agent_data.get('AgentVersion')
            ]

            # Chỉ kiểm tra các trường bắt buộc
            if not params[0] or not params[1] or not params[2] or not params[6]:
                logging.error(f"Skip insert agent with missing required fields: {params}")
                return False

            # Đăng ký agent vào bảng Agents
            insert_agent_query = """
            INSERT INTO Agents (Hostname, OSType, OSVersion, Architecture, IPAddress, MACAddress, AgentVersion, Status, IsActive, FirstSeen, LastHeartbeat, LastSeen)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'Online', 1, GETDATE(), GETDATE(), GETDATE())
            """
            self.db.execute_query(insert_agent_query, tuple(params))

            # Gán rules cho agent
            # 1. Lấy các rules global (IsGlobal = 1)
            select_global_rules_query = """
            SELECT RuleID FROM Rules
            WHERE IsActive = 1 AND IsGlobal = 1
            """
            global_rule_rows = self.db.execute_query(select_global_rules_query)
            global_rule_ids = [row[0] for row in global_rule_rows]

            # 2. Lấy các rules riêng cho OS (IsGlobal = 0 và OSType = ?)
            select_os_rules_query = """
            SELECT RuleID FROM Rules
            WHERE IsActive = 1 AND IsGlobal = 0 AND OSType = ?
            """
            os_rule_rows = self.db.execute_query(select_os_rules_query, (agent_data.get('OSType'),))
            os_rule_ids = [row[0] for row in os_rule_rows]

            # 3. Gán tất cả rules cho agent
            all_rule_ids = global_rule_ids + os_rule_ids
            for rule_id in all_rule_ids:
                insert_agent_rule_query = """
                IF NOT EXISTS (SELECT 1 FROM AgentRules WHERE RuleID = ? AND Hostname = ?)
                BEGIN
                    INSERT INTO AgentRules (RuleID, Hostname, IsActive, AppliedAt)
                    VALUES (?, ?, 1, GETDATE())
                END
                """
                self.db.execute_query(insert_agent_rule_query, (rule_id, agent_data.get('Hostname'), rule_id, agent_data.get('Hostname')))

            logging.info(f"Assigned {len(all_rule_ids)} rules to agent {agent_data.get('Hostname')} ({len(global_rule_ids)} global, {len(os_rule_ids)} OS-specific)")
            return True
        except Exception as e:
            logging.error(f"Error registering agent and assigning rules: {e}")
            return False

    def update_agent_status(self, hostname, is_online):
        """Cập nhật trạng thái online/offline cho agent"""
        try:
            status = 'Online' if is_online else 'Offline'
            query = "UPDATE Agents SET Status = ?, LastSeen = GETDATE() WHERE Hostname = ?"
            self.db.execute_query(query, (status, hostname))
            logging.info(f"Cập nhật trạng thái agent {hostname} thành {status}")
            return True
        except Exception as e:
            logging.error(f"Lỗi cập nhật trạng thái agent {hostname}: {e}")
            return False

    def get_agent_status(self, hostname):
        """Lấy trạng thái online/offline và thời gian cuối cùng của agent"""
        try:
            query = "SELECT Status FROM Agents WHERE Hostname = ?"
            cursor = self.db.execute_query(query, (hostname,))
            if cursor:
                result = cursor.fetchone()
                return result[0] if result else None
            return None
        except Exception:
            return None

    def get_agents(self, os_type=None):
        """Get list of agents."""
        try:
            query = """
                SELECT 
                    Hostname, OSType, OSVersion, Architecture,
                    IPAddress, Status, LastSeen
                FROM Agents
                WHERE IsActive = 1
                AND (? IS NULL OR OSType = ?)
                ORDER BY OSType, Hostname
            """
            return self.db.execute_query(query, (os_type, os_type))
        except Exception as e:
            print(f"Error getting agents: {e}")
            return []

    def get_agent_rules(self, hostname):
        """Get all rules assigned to an agent"""
        try:
            query = """
            SELECT r.RuleID 
            FROM Rules r
            JOIN AgentRules ar ON r.RuleID = ar.RuleID
            WHERE ar.Hostname = ?
            """
            rules = self.db.execute_query(query, (hostname,))
            return [rule[0] for rule in rules]  # Return list of RuleIDs
        except Exception as e:
            logging.error(f"Error getting agent rules: {e}")
            return [] 

    def assign_rule(self, hostname, rule_id):
        """Gán rule cho agent (nếu chưa có)"""
        try:
            query = """
            IF NOT EXISTS (SELECT 1 FROM AgentRules WHERE RuleID = ? AND Hostname = ?)
            BEGIN
                INSERT INTO AgentRules (RuleID, Hostname, IsActive, AppliedAt)
                VALUES (?, ?, 1, GETDATE())
            END
            """
            self.db.execute_query(query, (rule_id, hostname, rule_id, hostname))
            return True
        except Exception as e:
            logging.error(f"Error assigning rule {rule_id} to agent {hostname}: {e}")
            return False 

def get_db_connection():
    """Tạo kết nối đến database"""
    try:
        conn = sqlite3.connect('database/edr.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
        return None

def register_agent(agent_info):
    """Đăng ký agent mới"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Kiểm tra agent đã tồn tại chưa
        cursor.execute('SELECT * FROM agents WHERE hostname = ?', (agent_info['hostname'],))
        existing_agent = cursor.fetchone()
        
        if existing_agent:
            # Cập nhật thông tin agent
            cursor.execute('''
                UPDATE agents 
                SET ip_address = ?, os_info = ?, system_type = ?, status = ?, last_seen = CURRENT_TIMESTAMP
                WHERE hostname = ?
            ''', (
                agent_info['ip_address'],
                agent_info['os_info'],
                agent_info.get('system_type', 'Unknown'),
                agent_info.get('status', 'Online'),
                agent_info['hostname']
            ))
            logger.info(f"SUCCESS: Agent updated - {agent_info['hostname']}")
        else:
            # Thêm agent mới
            cursor.execute('''
                INSERT INTO agents (hostname, ip_address, os_info, system_type, status, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ''', (
                agent_info['hostname'],
                agent_info['ip_address'],
                agent_info['os_info'],
                agent_info.get('system_type', 'Unknown'),
                agent_info.get('status', 'Online')
            ))
            logger.info(f"SUCCESS: New agent registered - {agent_info['hostname']}")
            
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"ERROR: Failed to register agent - {e}")
        if conn:
            conn.close()
        return False

def update_agent_status(agent_info):
    """Cập nhật trạng thái agent"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Cập nhật trạng thái và thời gian cuối
        cursor.execute('''
            UPDATE agents 
            SET status = ?, last_seen = CURRENT_TIMESTAMP
            WHERE hostname = ?
        ''', (agent_info['status'], agent_info['hostname']))
        
        if cursor.rowcount > 0:
            logger.info(f"SUCCESS: Agent status updated - {agent_info['hostname']} ({agent_info['status']})")
        else:
            logger.warning(f"Agent not found: {agent_info['hostname']}")
            
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"ERROR: Failed to update agent status - {e}")
        if conn:
            conn.close()
        return False

def update_agent_heartbeat(hostname):
    """Cập nhật heartbeat của agent"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Cập nhật thời gian cuối
        cursor.execute('''
            UPDATE agents 
            SET last_seen = CURRENT_TIMESTAMP
            WHERE hostname = ?
        ''', (hostname,))
        
        if cursor.rowcount > 0:
            logger.debug(f"Agent heartbeat updated - {hostname}")
        else:
            logger.warning(f"Agent not found: {hostname}")
            
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"ERROR: Failed to update agent heartbeat - {e}")
        if conn:
            conn.close()
        return False

def get_agent_status(hostname):
    """Lấy trạng thái của agent"""
    try:
        conn = get_db_connection()
        if not conn:
            return None
            
        cursor = conn.cursor()
        cursor.execute('SELECT status, last_seen FROM agents WHERE hostname = ?', (hostname,))
        agent = cursor.fetchone()
        
        conn.close()
        
        if agent:
            # Kiểm tra nếu agent không hoạt động trong 5 phút
            last_seen = datetime.strptime(agent['last_seen'], '%Y-%m-%d %H:%M:%S')
            if datetime.now() - last_seen > timedelta(minutes=5):
                return 'Offline'
            return agent['status']
        return None
        
    except Exception as e:
        logger.error(f"ERROR: Failed to get agent status - {e}")
        if conn:
            conn.close()
        return None

def get_all_agents():
    """Lấy danh sách tất cả agent"""
    try:
        conn = get_db_connection()
        if not conn:
            return []
            
        cursor = conn.cursor()
        cursor.execute('''
            SELECT hostname, ip_address, os_info, system_type, status, first_seen, last_seen
            FROM agents
            ORDER BY last_seen DESC
        ''')
        
        agents = []
        for row in cursor.fetchall():
            # Kiểm tra trạng thái thực tế
            last_seen = datetime.strptime(row['last_seen'], '%Y-%m-%d %H:%M:%S')
            status = row['status']
            if datetime.now() - last_seen > timedelta(minutes=5):
                status = 'Offline'
                
            agents.append({
                'hostname': row['hostname'],
                'ip_address': row['ip_address'],
                'os_info': row['os_info'],
                'system_type': row['system_type'],
                'status': status,
                'first_seen': row['first_seen'],
                'last_seen': row['last_seen']
            })
            
        conn.close()
        return agents
        
    except Exception as e:
        logger.error(f"ERROR: Failed to get agents - {e}")
        if conn:
            conn.close()
        return []

def cleanup_offline_agents():
    """Dọn dẹp các agent offline"""
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Cập nhật trạng thái các agent không hoạt động trong 5 phút
        cursor.execute('''
            UPDATE agents 
            SET status = 'Offline'
            WHERE datetime(last_seen) < datetime('now', '-5 minutes')
            AND status != 'Offline'
        ''')
        
        if cursor.rowcount > 0:
            logger.info(f"SUCCESS: Marked {cursor.rowcount} agents as offline")
            
        conn.commit()
        conn.close()
        return True
        
    except Exception as e:
        logger.error(f"ERROR: Failed to cleanup offline agents - {e}")
        if conn:
            conn.close()
            return False 