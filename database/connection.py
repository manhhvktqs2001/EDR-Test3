import pyodbc
import logging
import time
from typing import Optional
from config import DB_SETTINGS

class DatabaseConnection:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.in_transaction = False

    def connect(self):
        """Kết nối đến database"""
        try:
            if self.conn:
                self.close()
                
            self.conn = pyodbc.connect(DB_SETTINGS['connection_string'], autocommit=True)
            self.cursor = self.conn.cursor()
            logging.info("Database connection established successfully")
            return True
        except Exception as e:
            logging.error(f"Error connecting to database: {e}")
            return False

    def check_connection(self):
        """Kiểm tra kết nối database"""
        try:
            if not self.conn:
                return self.connect()
                
            # Test connection
            self.cursor.execute("SELECT 1")
            self.cursor.fetchone()
            return True
        except Exception as e:
            logging.error(f"Error checking connection: {e}")
            return self.connect()

    def close(self):
        """Đóng kết nối database"""
        try:
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            if self.conn:
                self.conn.close()
                self.conn = None
            logging.info("Database connection closed")
        except Exception as e:
            logging.error(f"Error closing connection: {e}")

    def begin_transaction(self):
        """Bắt đầu transaction"""
        try:
            if not self.in_transaction and self.conn:
                self.in_transaction = True
                self.conn.autocommit = False
                logging.debug("Transaction started")
        except Exception as e:
            logging.error(f"Error starting transaction: {e}")

    def commit(self):
        """Commit transaction"""
        if self.in_transaction and self.conn:
            try:
                self.conn.commit()
                self.in_transaction = False
                self.conn.autocommit = True
                logging.debug("Transaction committed")
            except Exception as e:
                logging.error(f"Error committing transaction: {e}")
                self.rollback()

    def rollback(self):
        """Rollback transaction"""
        if self.in_transaction and self.conn:
            try:
                self.conn.rollback()
                self.in_transaction = False
                self.conn.autocommit = True
                logging.debug("Transaction rolled back")
            except Exception as e:
                logging.error(f"Error rolling back transaction: {e}")

    def execute_query(self, query, params=None):
        """Thực thi query"""
        try:
            if not self.check_connection():
                return None
                
            # Clear any pending results
            try:
                while self.cursor.nextset():
                    pass
            except:
                # Ignore error if no more result sets
                pass
                
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
                
            # Only commit if not in transaction
            if not self.in_transaction and self.conn:
                self.conn.commit()
                
            return self.cursor
            
        except Exception as e:
            logging.error(f"Error executing query: {e}")
            logging.error(f"Query: {query}")
            logging.error(f"Params: {params}")
            
            # Only rollback if not in transaction
            if not self.in_transaction and self.conn:
                try:
                    self.conn.rollback()
                except:
                    pass
            return None

    def execute_many(self, query: str, params_list: list) -> bool:
        """Thực thi nhiều query trong một transaction"""
        try:
            if not self.check_connection():
                if not self.connect():
                    return False
                    
            self.begin_transaction()
            
            try:
                self.cursor.executemany(query, params_list)
                self.commit()
                return True
            except Exception as e:
                self.rollback()
                raise e
            
        except Exception as e:
            logging.error(f"Error executing batch queries: {e}")
            logging.error(f"Query: {query}")
            logging.error(f"Params count: {len(params_list) if params_list else 0}")
            return False

    def fetch_one(self, query, params=None):
        """Thực thi query và trả về một row"""
        try:
            cursor = self.execute_query(query, params)
            if cursor:
                return cursor.fetchone()
            return None
        except Exception as e:
            logging.error(f"Error fetching one row: {e}")
            return None

    def fetch_all(self, query, params=None):
        """Thực thi query và trả về tất cả rows"""
        try:
            cursor = self.execute_query(query, params)
            if cursor:
                return cursor.fetchall()
            return []
        except Exception as e:
            logging.error(f"Error fetching all rows: {e}")
            return []

    def execute_non_query(self, query, params=None):
        """Thực thi query không trả về dữ liệu (INSERT, UPDATE, DELETE)"""
        try:
            cursor = self.execute_query(query, params)
            if cursor:
                return cursor.rowcount
            return 0
        except Exception as e:
            logging.error(f"Error executing non-query: {e}")
            return 0

    def is_connected(self):
        """Kiểm tra xem có đang kết nối không"""
        try:
            if not self.conn:
                return False
            # Test với một query đơn giản
            self.cursor.execute("SELECT 1")
            self.cursor.fetchone()
            return True
        except:
            return False

    def get_table_exists(self, table_name):
        """Kiểm tra xem table có tồn tại không"""
        try:
            query = """
            SELECT COUNT(*) 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_NAME = ?
            """
            result = self.fetch_one(query, (table_name,))
            return result[0] > 0 if result else False
        except Exception as e:
            logging.error(f"Error checking table existence: {e}")
            return False

    def __enter__(self):
        """Context manager entry"""
        if not self.connect():
            raise Exception("Failed to connect to database")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        if exc_type is not None:
            logging.error(f"Exception in context manager: {exc_type}: {exc_val}")
            self.rollback()
        self.close()
        
    def __del__(self):
        """Destructor để đảm bảo connection được đóng"""
        try:
            self.close()
        except:
            pass