from .connection import DatabaseConnection
from datetime import datetime
import logging
import time
import json
import hashlib
import os
from .rules import RuleDB
from .alerts import AlertDB
import sqlite3
from datetime import timedelta

logger = logging.getLogger(__name__)

def calculate_file_hash(filepath):
    """Calculate MD5 hash of a file"""
    try:
        if not filepath or not os.path.exists(filepath):
            return ''
        hash_md5 = hashlib.md5()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating file hash: {e}")
        return ''

class LogDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()
        self.rule_db = RuleDB()
        self.alert_db = AlertDB()

    def insert_process_logs(self, logs):
        """Insert process logs in batches"""
        try:
            cursor = self.db.conn.cursor()
            success = 0
            failed = 0
            batch = []
            
            for log in logs:
                try:
                    # Time - use datetime.now() as default if not provided
                    time_val = log.get('Time', datetime.now())
                    if not time_val or str(time_val).strip().upper() == 'NULL':
                        time_val = datetime.now()
                    
                    # ParentProcessID
                    parent_pid = log.get('ParentProcessID')
                    if parent_pid is None or str(parent_pid).strip().upper() == 'NULL':
                        parent_pid = 0
                    else:
                        try:
                            parent_pid = int(parent_pid)
                        except Exception:
                            parent_pid = 0
                    
                    # Hash
                    hash_val = log.get('Hash')
                    if not hash_val or str(hash_val).strip().upper() == 'NULL':
                        hash_val = calculate_file_hash(log.get('ExecutablePath'))
                    else:
                        hash_val = str(hash_val)

                    # Đảm bảo không có None/NULL trong batch
                    row = [
                        time_val,
                        log.get('Hostname') or '',
                        log.get('ProcessID') if log.get('ProcessID') is not None and str(log.get('ProcessID')).strip().upper() != 'NULL' else 0,
                        parent_pid,
                        log.get('ProcessName') or '',
                        log.get('CommandLine') or '',
                        log.get('ExecutablePath') or '',
                        log.get('UserName') or '',
                        log.get('CPUUsage') if log.get('CPUUsage') is not None and str(log.get('CPUUsage')).strip().upper() != 'NULL' else 0.0,
                        log.get('MemoryUsage') if log.get('MemoryUsage') is not None and str(log.get('MemoryUsage')).strip().upper() != 'NULL' else 0,
                        hash_val
                    ]
                    
                    # Lớp kiểm tra cuối cùng: ép mọi giá trị None/'NULL' về mặc định
                    for i, v in enumerate(row):
                        if v is None or (isinstance(v, str) and v.strip().upper() == 'NULL'):
                            if i == 0:
                                row[i] = datetime.now()  # Time
                            elif i == 1:
                                row[i] = ''  # Hostname
                            elif i == 2:
                                row[i] = 0  # ProcessID
                            elif i == 3:
                                row[i] = 0  # ParentProcessID
                            elif i == 4:
                                row[i] = ''  # ProcessName
                            elif i == 5:
                                row[i] = ''  # CommandLine
                            elif i == 6:
                                row[i] = ''  # ExecutablePath
                            elif i == 7:
                                row[i] = ''  # UserName
                            elif i == 8:
                                row[i] = 0.0  # CPUUsage
                            elif i == 9:
                                row[i] = 0  # MemoryUsage
                            elif i == 10:
                                row[i] = ''  # Hash
                                
                    print("DEBUG batch data:", tuple(row))  # Log dữ liệu để debug
                    batch.append(tuple(row))
                    
                    if len(batch) >= 50:
                        if self.execute_batch_with_timeout(cursor, """
                            INSERT INTO ProcessLogs (
                                Time, Hostname, ProcessID, ParentProcessID,
                                ProcessName, CommandLine, ExecutablePath,
                                UserName, CPUUsage, MemoryUsage, Hash
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, batch):
                            success += len(batch)
                        else:
                            failed += len(batch)
                        batch = []
                        self.db.conn.commit()
                        
                except Exception as e:
                    logging.error(f"Error processing process log: {e}")
                    failed += 1
                    continue
            
            if batch:
                if self.execute_batch_with_timeout(cursor, """
                    INSERT INTO ProcessLogs (
                        Time, Hostname, ProcessID, ParentProcessID,
                        ProcessName, CommandLine, ExecutablePath,
                        UserName, CPUUsage, MemoryUsage, Hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch):
                    success += len(batch)
                else:
                    failed += len(batch)
                self.db.conn.commit()

            return success, failed

        except Exception as e:
            logging.error(f"Error inserting process logs: {e}")
            self.db.conn.rollback()
            return 0, len(logs)

    def insert_network_logs(self, logs):
        """Insert network logs in batches"""
        try:
            cursor = self.db.conn.cursor()
            success = 0
            failed = 0
            batch = []
            
            for log in logs:
                try:
                    batch.append((
                        log['Hostname'],
                        log['Time'],
                        log['ProcessID'],
                        log['ProcessName'],
                        log.get('Protocol', 'Unknown'),
                        log.get('LocalAddress', ''),
                        log.get('LocalPort', 0),
                        log.get('RemoteAddress', ''),
                        log.get('RemotePort', 0),
                        log.get('Direction', 'Unknown')
                    ))
                    
                    if len(batch) >= 50:
                        if self.execute_batch_with_timeout(cursor, """
                            INSERT INTO NetworkLogs (
                                Hostname, Time, ProcessID, ProcessName,
                                Protocol, LocalAddress, LocalPort,
                                RemoteAddress, RemotePort, Direction
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, batch):
                            success += len(batch)
                        else:
                            failed += len(batch)
                        batch = []
                        self.db.conn.commit()
                        
                except Exception as e:
                    logging.error(f"Error processing network log: {e}")
                    failed += 1
                    continue
            
            if batch:
                if self.execute_batch_with_timeout(cursor, """
                    INSERT INTO NetworkLogs (
                        Hostname, Time, ProcessID, ProcessName,
                        Protocol, LocalAddress, LocalPort,
                        RemoteAddress, RemotePort, Direction
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch):
                    success += len(batch)
                else:
                    failed += len(batch)
                self.db.conn.commit()

            return success, failed

        except Exception as e:
            logging.error(f"Error inserting network logs: {e}")
            self.db.conn.rollback()
            return 0, len(logs)

    def insert_file_logs(self, logs):
        """Insert file logs in batches"""
        try:
            cursor = self.db.conn.cursor()
            success = 0
            failed = 0
            batch = []
            
            for log in logs:
                try:
                    # Chuẩn bị dữ liệu với giá trị mặc định
                    data = {
                        'Time': log.get('Time'),
                        'Hostname': log.get('Hostname'),
                        'FileName': log.get('FileName'),
                        'FilePath': log.get('FilePath'),
                        'FileSize': log.get('FileSize', 0),
                        'FileHash': log.get('FileHash', ''),
                        'EventType': log.get('EventType'),
                        'ProcessID': log.get('ProcessID', 0),
                        'ProcessName': log.get('ProcessName', '')
                    }

                    # Kiểm tra các trường bắt buộc
                    required_fields = ['Time', 'Hostname', 'EventType', 'FileName', 'FilePath']
                    if not all(data.get(field) for field in required_fields):
                        logging.error(f"Missing required fields in file log: {log}")
                        failed += 1
                        continue

                    batch.append((
                        data['Time'],
                        data['Hostname'],
                        data['FileName'],
                        data['FilePath'],
                        data['FileSize'],
                        data['FileHash'],
                        data['EventType'],
                        data['ProcessID'],
                        data['ProcessName']
                    ))
                    
                    if len(batch) >= 50:
                        query = """
                            INSERT INTO FileLogs (
                                Time, Hostname, FileName, FilePath,
                                FileSize, FileHash, EventType,
                                ProcessID, ProcessName
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """
                        if self.execute_batch_with_timeout(cursor, query, batch):
                            success += len(batch)
                        else:
                            failed += len(batch)
                        batch = []
                        self.db.conn.commit()
                        
                except Exception as e:
                    logging.error(f"Error processing file log: {e}")
                    failed += 1
                    continue
            
            if batch:
                query = """
                    INSERT INTO FileLogs (
                        Time, Hostname, FileName, FilePath,
                        FileSize, FileHash, EventType,
                        ProcessID, ProcessName
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                if self.execute_batch_with_timeout(cursor, query, batch):
                    success += len(batch)
                else:
                    failed += len(batch)
                self.db.conn.commit()

            return success, failed

        except Exception as e:
            logging.error(f"Error inserting file logs: {e}")
            self.db.conn.rollback()
            return 0, len(logs)

    def execute_with_timeout(self, cursor, query, params=None, timeout=30):
        """Execute query with timeout"""
        try:
            cursor.execute("SET LOCK_TIMEOUT ?", (timeout * 1000,))
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            return True
        except Exception as e:
            logging.error(f"Query timeout or error: {e}")
            return False

    def execute_batch_with_timeout(self, cursor, query, batch, timeout=30):
        """Execute batch query with timeout"""
        try:
            cursor.execute("SET LOCK_TIMEOUT ?", (timeout * 1000,))
            cursor.executemany(query, batch)
            return True
        except Exception as e:
            logging.error(f"Batch query timeout or error: {e}")
            return False

    def is_valid_hostname(self, hostname):
        query = "SELECT 1 FROM Agents WHERE Hostname = ?"
        result = self.db.execute_query(query, (hostname,))
        return bool(result)

    def process_log(self, log_type, log_data):
        """Process and store log data"""
        try:
            if not log_data:
                logging.error("ERROR: Empty log data received")
                return False
                
            # Validate required fields based on log type
            required_fields = {
                'process': ['Time', 'Hostname', 'ProcessID', 'ProcessName', 'CommandLine', 
                           'ExecutablePath', 'UserName', 'CPUUsage', 'MemoryUsage'],
                'file': ['Time', 'Hostname', 'FileName', 'FilePath', 'FileSize', 
                        'FileHash', 'EventType', 'ProcessID', 'ProcessName'],
                'network': ['Time', 'Hostname', 'ProcessID', 'ProcessName', 'Protocol',
                           'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'Direction']
            }

            if log_type not in required_fields:
                logging.error(f"ERROR: Invalid log type: {log_type}")
                return False
                
            missing_fields = [field for field in required_fields[log_type] if field not in log_data]
            if missing_fields:
                logging.error(f"ERROR: Missing required fields for {log_type} log: {missing_fields}")
                return False
                
            # Process based on log type
            if log_type == 'process':
                return self._process_process_log(log_data)
            elif log_type == 'file':
                return self._process_file_log(log_data)
            elif log_type == 'network':
                return self._process_network_log(log_data)

        except Exception as e:
            logging.error(f"ERROR: Failed to process {log_type} log - {e}")
            return False
                
    def _process_process_log(self, log_data):
        """Process and store process log"""
        try:
            query = """
            INSERT INTO ProcessLogs (
                Time, Hostname, ProcessID, ProcessName, CommandLine,
                ExecutablePath, UserName, CPUUsage, MemoryUsage
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                log_data['Time'],
                log_data['Hostname'],
                log_data['ProcessID'],
                log_data['ProcessName'],
                log_data['CommandLine'],
                log_data['ExecutablePath'],
                log_data['UserName'],
                log_data['CPUUsage'],
                log_data['MemoryUsage']
            )
            
            with self.db.conn.cursor() as cursor:
                cursor.execute(query, params)
                self.db.conn.commit()
                logging.info(f"SUCCESS: Process log inserted for {log_data['Hostname']} - PID: {log_data['ProcessID']}")
                return True
            
        except Exception as e:
            logging.error(f"ERROR: Failed to insert process log - {e}")
            return False

    def _process_file_log(self, log_data):
        """Process and store file log"""
        try:
            # Log thông tin chi tiết về log đang xử lý
            logging.info(f"Processing file log: {log_data['FileName']} ({log_data['EventType']}) from {log_data['Hostname']}")
            
            query = """
            INSERT INTO FileLogs (
                Time, Hostname, FileName, FilePath, FileSize,
                FileHash, EventType, ProcessID, ProcessName
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                log_data['Time'],
                log_data['Hostname'],
                log_data['FileName'],
                log_data['FilePath'],
                log_data['FileSize'],
                log_data['FileHash'],
                log_data['EventType'],
                log_data['ProcessID'],
                log_data['ProcessName']
            )
            
            with self.db.conn.cursor() as cursor:
                cursor.execute(query, params)
                self.db.conn.commit()
                logging.info(f"SUCCESS: File log inserted for {log_data['Hostname']} - File: {log_data['FileName']} ({log_data['EventType']})")
            return True
            
        except Exception as e:
            logging.error(f"ERROR: Failed to insert file log - {e}")
            logging.error(f"Log data: {log_data}")
            return False

    def _process_network_log(self, log_data):
        """Process and store network log"""
        try:
            query = """
            INSERT INTO NetworkLogs (
                Time, Hostname, ProcessID, ProcessName, Protocol,
                LocalAddress, LocalPort, RemoteAddress, RemotePort, Direction
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            params = (
                log_data['Time'],
                log_data['Hostname'],
                log_data['ProcessID'],
                log_data['ProcessName'],
                log_data['Protocol'],
                log_data['LocalAddress'],
                log_data['LocalPort'],
                log_data['RemoteAddress'],
                log_data['RemotePort'],
                log_data['Direction']
            )
            
            with self.db.conn.cursor() as cursor:
                cursor.execute(query, params)
                self.db.conn.commit()
                logging.info(f"SUCCESS: Network log inserted for {log_data['Hostname']} - Process: {log_data['ProcessName']}")
            return True

        except Exception as e:
            logging.error(f"ERROR: Failed to insert network log - {e}")
            return False

    def get_process_logs(self, hostname=None, from_time=None, to_time=None, limit=100):
        """Get process logs with optional filters"""
        try:
            cursor = self.db.conn.cursor()
            query = "SELECT * FROM ProcessLogs WHERE 1=1"
            params = []
            
            if hostname:
                query += " AND Hostname = ?"
                params.append(hostname)
            if from_time:
                query += " AND Time >= ?"
                params.append(from_time)
            if to_time:
                query += " AND Time <= ?"
                params.append(to_time)
                
            query += " ORDER BY Time DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return cursor.fetchall()

        except Exception as e:
            logging.error(f"Error getting process logs: {e}")
            return []

    def get_file_logs(self, hostname=None, from_time=None, to_time=None, limit=100):
        """Get file logs with optional filters"""
        try:
            cursor = self.db.conn.cursor()
            query = "SELECT * FROM FileLogs WHERE 1=1"
            params = []
            
            if hostname:
                query += " AND Hostname = ?"
                params.append(hostname)
            if from_time:
                query += " AND Time >= ?"
                params.append(from_time)
            if to_time:
                query += " AND Time <= ?"
                params.append(to_time)
                
            query += " ORDER BY Time DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return cursor.fetchall()

        except Exception as e:
            logging.error(f"Error getting file logs: {e}")
            return []

    def get_network_logs(self, hostname=None, from_time=None, to_time=None, limit=100):
        """Get network logs with optional filters"""
        try:
            cursor = self.db.conn.cursor()
            query = "SELECT * FROM NetworkLogs WHERE 1=1"
            params = []
            
            if hostname:
                query += " AND Hostname = ?"
                params.append(hostname)
            if from_time:
                query += " AND Time >= ?"
                params.append(from_time)
            if to_time:
                query += " AND Time <= ?"
                params.append(to_time)
                
            query += " ORDER BY Time DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return cursor.fetchall()

        except Exception as e:
            logging.error(f"Error getting network logs: {e}")
            return []

def get_db_connection():
    """Tạo kết nối đến database"""
    try:
        conn = sqlite3.connect('edr.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        logger.error(f"Error connecting to database: {e}")
        return None

def create_log(log_type, log_data):
    """Tạo log mới trong database
    
    Args:
        log_type (str): Loại log ('process', 'file', 'network')
        log_data (dict): Dữ liệu log
        
    Returns:
        bool: True nếu tạo thành công, False nếu thất bại
    """
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Chuẩn bị dữ liệu log
        log_values = {
            'Hostname': log_data.get('Hostname', ''),
            'Time': log_data.get('Time', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            'EventType': log_data.get('EventType', ''),
            'ProcessID': log_data.get('ProcessID', ''),
            'ProcessName': log_data.get('ProcessName', ''),
            'UserName': log_data.get('UserName', ''),
            'CommandLine': log_data.get('CommandLine', ''),
            'ExecutablePath': log_data.get('ExecutablePath', ''),
            'CPUUsage': log_data.get('CPUUsage', 0),
            'MemoryUsage': log_data.get('MemoryUsage', 0),
            'FileName': log_data.get('FileName', ''),
            'FilePath': log_data.get('FilePath', ''),
            'FileSize': log_data.get('FileSize', 0),
            'FileHash': log_data.get('FileHash', ''),
            'Protocol': log_data.get('Protocol', ''),
            'LocalAddress': log_data.get('LocalAddress', ''),
            'LocalPort': log_data.get('LocalPort', 0),
            'RemoteAddress': log_data.get('RemoteAddress', ''),
            'RemotePort': log_data.get('RemotePort', 0),
            'Direction': log_data.get('Direction', ''),
            'Status': log_data.get('Status', ''),
            'CreatedAt': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Xác định bảng và cột dựa vào loại log
        if log_type == 'process':
            table = 'process_logs'
            columns = [
                'Hostname', 'Time', 'EventType', 'ProcessID', 'ProcessName',
                'UserName', 'CommandLine', 'ExecutablePath', 'CPUUsage',
                'MemoryUsage', 'CreatedAt'
            ]
        elif log_type == 'file':
            table = 'file_logs'
            columns = [
                'Hostname', 'Time', 'EventType', 'ProcessID', 'ProcessName',
                'FileName', 'FilePath', 'FileSize', 'FileHash', 'CreatedAt'
            ]
        elif log_type == 'network':
            table = 'network_logs'
            columns = [
                'Hostname', 'Time', 'EventType', 'ProcessID', 'ProcessName',
                'Protocol', 'LocalAddress', 'LocalPort', 'RemoteAddress',
                'RemotePort', 'Direction', 'Status', 'CreatedAt'
            ]
        else:
            logger.error(f"Invalid log type: {log_type}")
            return False
            
        # Tạo câu lệnh SQL
        placeholders = ', '.join(['?' for _ in columns])
        columns_str = ', '.join(columns)
        sql = f"INSERT INTO {table} ({columns_str}) VALUES ({placeholders})"
        
        # Thực thi câu lệnh
        values = [log_values[col] for col in columns]
        cursor.execute(sql, values)
        
        conn.commit()
        conn.close()
        
        logger.info(f"Created new {log_type} log for host {log_values['Hostname']}")
        return True
        
    except Exception as e:
        logger.error(f"Error creating log: {e}")
        return False

def get_logs(log_type, hostname=None, from_time=None, to_time=None, limit=100):
    """Lấy danh sách logs từ database
    
    Args:
        log_type (str): Loại log ('process', 'file', 'network')
        hostname (str, optional): Lọc theo hostname
        from_time (str, optional): Thời gian bắt đầu
        to_time (str, optional): Thời gian kết thúc
        limit (int, optional): Số lượng log tối đa
        
    Returns:
        list: Danh sách logs
    """
    try:
        conn = get_db_connection()
        if not conn:
            return []
            
        cursor = conn.cursor()
        
        # Xác định bảng dựa vào loại log
        if log_type == 'process':
            table = 'process_logs'
        elif log_type == 'file':
            table = 'file_logs'
        elif log_type == 'network':
            table = 'network_logs'
        else:
            logger.error(f"Invalid log type: {log_type}")
            return []
            
        # Tạo câu lệnh SQL
        sql = f"SELECT * FROM {table} WHERE 1=1"
        params = []
        
        if hostname:
            sql += " AND Hostname = ?"
            params.append(hostname)
            
        if from_time:
            sql += " AND Time >= ?"
            params.append(from_time)
            
        if to_time:
            sql += " AND Time <= ?"
            params.append(to_time)
            
        sql += f" ORDER BY Time DESC LIMIT {limit}"
        
        # Thực thi câu lệnh
        cursor.execute(sql, params)
        logs = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        return logs
        
    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return [] 

def delete_old_logs(days=30):
    """Xóa logs cũ
    
    Args:
        days (int): Số ngày giữ lại logs
        
    Returns:
        bool: True nếu xóa thành công, False nếu thất bại
    """
    try:
        conn = get_db_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
        
        # Xóa logs cũ từ mỗi bảng
        for table in ['process_logs', 'file_logs', 'network_logs']:
            cursor.execute(f"DELETE FROM {table} WHERE Time < ?", (cutoff_date,))
            
        conn.commit()
        conn.close()
        
        logger.info(f"Deleted logs older than {days} days")
        return True
        
    except Exception as e:
        logger.error(f"Error deleting old logs: {e}")
        return False