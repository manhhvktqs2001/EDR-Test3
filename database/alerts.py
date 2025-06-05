import logging
from .connection import DatabaseConnection
import json

class AlertDB:
    def __init__(self):
        self.db = DatabaseConnection()
        self.db.connect()

    def get_alerts(self, severity=None, status=None, from_date=None, to_date=None):
        try:
            query = "SELECT * FROM Alerts WHERE 1=1"
            params = []
            if severity:
                query += " AND [Severity] = ?"
                params.append(severity)
            if status:
                query += " AND [Status] = ?"
                params.append(status)
            if from_date:
                query += " AND [Time] >= ?"
                params.append(from_date)
            if to_date:
                query += " AND [Time] <= ?"
                params.append(to_date)
            query += " ORDER BY [Time] DESC"
            rows = self.db.execute_query(query, tuple(params))
            alerts = []
            if rows:
                for row in rows:
                    try:
                        alerts.append({
                            "alert_id": row.AlertID,
                            "time": row.Time.strftime('%Y-%m-%d %H:%M:%S') if hasattr(row, 'Time') and row.Time else None,
                            "hostname": row.Hostname,
                            "rule_id": row.RuleID,
                            "alert_type": row.AlertType,
                            "severity": row.Severity,
                            "status": row.Status,
                            "title": row.Title,
                            "description": row.Description,
                            "detection_data": row.DetectionData,
                            "action": row.Action
                        })
                    except Exception as e:
                        logging.error(f"Error parsing alert: {e}")
            return alerts
        except Exception as e:
            logging.error(f"Error fetching alerts: {e}")
            return []

    def insert_alert(self, hostname, rule_id, alert_type, severity, status, title, description, detection_data='', action=''):
        try:
            # Kiểm tra các trường bắt buộc
            if not all([hostname, rule_id, alert_type, severity, status, title, description]):
                return False
                
            # Kiểm tra rule_id hợp lệ
            if not self.db.execute_query("SELECT 1 FROM Rules WHERE RuleID = ?", (rule_id,)):
                return False
                
            self.db.begin_transaction()
            
            query = """
            INSERT INTO Alerts (Time, Hostname, RuleID, AlertType, Severity, Status, Title, Description, DetectionData, Action)
                VALUES (GETDATE(), ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            params = (hostname, rule_id, alert_type, severity, status, title, description, detection_data, action)
            
            if self.db.execute_query(query, params):
                self.db.commit()
                return True
            else:
                self.db.rollback()
                return False
                
        except Exception:
            self.db.rollback()
            return False

    def is_valid_rule_id(self, rule_id):
        query = "SELECT 1 FROM Rules WHERE RuleID = ?"
        result = self.db.execute_query(query, (rule_id,))
        return bool(result)

    def get_alerts(self, start_time=None, end_time=None, severity=None, status=None, hostname=None):
        """Get alerts with optional filters."""
        try:
            # Use stored procedure if available
            params = (start_time, end_time, severity, status, hostname)
            return self.db.execute_procedure('sp_GetAlertsDashboard', params)
        except:
            # Fallback to direct query if procedure not available
            query = """
            SELECT 
                a.AlertID, a.Time, a.Hostname, a.AlertType, a.Severity,
                a.Status, a.Title, a.Description, r.RuleName, r.RuleType,
                r.Action as RuleAction, ag.OSType as AgentOSType,
                a.DetectionData, a.Action
            FROM Alerts a
            JOIN Rules r ON a.RuleID = r.RuleID
            JOIN Agents ag ON a.Hostname = ag.Hostname
            WHERE 1=1
            """
            params = []
            
            if start_time:
                query += " AND a.Time >= ?"
                params.append(start_time)
            if end_time:
                query += " AND a.Time <= ?"
                params.append(end_time)
            if severity:
                query += " AND a.Severity = ?"
                params.append(severity)
            if status:
                query += " AND a.Status = ?"
                params.append(status)
            if hostname:
                query += " AND a.Hostname = ?"
                params.append(hostname)
                
            query += " ORDER BY a.Time DESC"
            return self.db.execute_query(query, tuple(params))

    def update_alert_status(self, alert_id, status):
        try:
            query = "UPDATE Alerts SET Status = ? WHERE AlertID = ?"
            if self.db.execute_query(query, (status, alert_id)):
                return True
            return False
        except Exception:
            return False

    def get_alert_stats(self, start_time=None, end_time=None):
        """Get alert statistics."""
        try:
            # Use stored procedure if available
            params = (start_time, end_time)
            return self.db.execute_procedure('sp_GetDashboardOverview', params)
        except:
            # Fallback to direct query if procedure not available
            query = """
            SELECT 
                Severity,
                COUNT(*) as AlertCount,
                SUM(CASE WHEN Status = 'New' THEN 1 ELSE 0 END) as NewAlerts,
                SUM(CASE WHEN Status = 'In Progress' THEN 1 ELSE 0 END) as InProgressAlerts,
                SUM(CASE WHEN Status = 'Resolved' THEN 1 ELSE 0 END) as ResolvedAlerts
            FROM Alerts
            WHERE 1=1
            """
            params = []
            
            if start_time:
                query += " AND Time >= ?"
                params.append(start_time)
            if end_time:
                query += " AND Time <= ?"
                params.append(end_time)
                
            query += " GROUP BY Severity"
            return self.db.execute_query(query, tuple(params)) 

    def create_alert(self, hostname, rule_id, alert_type, message, severity, detection_data):
        """Create a new alert"""
        try:
            query = """
            INSERT INTO Alerts (
                Hostname, RuleID, AlertType, Message,
                Severity, DetectionData, Status, CreatedAt
            ) VALUES (?, ?, ?, ?, ?, ?, 'New', GETDATE())
            """
            params = (
                hostname,
                rule_id,
                alert_type,
                message,
                severity,
                detection_data
            )
            
            with self.db.conn.cursor() as cursor:
                cursor.execute(query, params)
                self.db.conn.commit()
                logging.info(f"SUCCESS: Alert created - {hostname} - RuleID: {rule_id}")
                return True
                
        except Exception as e:
            logging.error(f"ERROR: Failed to create alert - {e}")
            return False

    def update_alert_status(self, alert_id, status, action=None):
        """Update alert status"""
        try:
            query = """
            UPDATE Alerts SET
                Status = ?,
                Action = ?,
                UpdatedAt = GETDATE()
            WHERE AlertID = ?
            """
            params = (status, action, alert_id)
            
            with self.db.conn.cursor() as cursor:
                cursor.execute(query, params)
                self.db.conn.commit()
                logging.info(f"SUCCESS: Alert status updated - ID: {alert_id} ({status})")
                return True
                
        except Exception as e:
            logging.error(f"ERROR: Failed to update alert status - {e}")
            return False

    def get_alerts(self, severity=None, status=None, from_date=None, to_date=None):
        """Get alerts with optional filters"""
        try:
            query = "SELECT * FROM Alerts WHERE 1=1"
            params = []
            
            if severity:
                query += " AND Severity = ?"
                params.append(severity)
            if status:
                query += " AND Status = ?"
                params.append(status)
            if from_date:
                query += " AND CreatedAt >= ?"
                params.append(from_date)
            if to_date:
                query += " AND CreatedAt <= ?"
                params.append(to_date)
                
            query += " ORDER BY CreatedAt DESC"
            
            with self.db.conn.cursor() as cursor:
                cursor.execute(query, params)
                return cursor.fetchall()
                
        except Exception as e:
            logging.error(f"ERROR: Failed to get alerts - {e}")
            return [] 