import pyodbc
import logging
import time
import re
from typing import Optional, Dict, List, Any, Tuple
from config import DB_SETTINGS, DATABASE_SCHEMA, FIELD_VALIDATION

class DatabaseConnection:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.in_transaction = False
        self.schema_cache = {}
        self._load_schema_cache()

    def _load_schema_cache(self):
        """Load database schema information into cache"""
        self.schema_cache = DATABASE_SCHEMA.copy()
        logging.info("Database schema cache loaded")

    def connect(self):
        """Establish database connection"""
        try:
            if self.conn:
                self.close()
                
            self.conn = pyodbc.connect(
                DB_SETTINGS['connection_string'], 
                autocommit=DB_SETTINGS.get('autocommit', True),
                timeout=DB_SETTINGS.get('timeout', 30)
            )
            self.cursor = self.conn.cursor()
            logging.info("Database connection established successfully")
            return True
        except Exception as e:
            logging.error(f"Error connecting to database: {e}")
            return False

    def check_connection(self):
        """Check and maintain database connection"""
        try:
            if not self.conn:
                return self.connect()
                
            # Test connection with simple query
            self.cursor.execute("SELECT 1")
            self.cursor.fetchone()
            return True
        except Exception as e:
            logging.error(f"Connection check failed: {e}")
            return self.connect()

    def get_table_schema(self, table_name: str) -> Dict:
        """Get table schema from cache or database"""
        if table_name in self.schema_cache:
            return self.schema_cache[table_name]
        
        # If not in cache, query database for schema
        try:
            schema_query = """
                SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
                FROM INFORMATION_SCHEMA.COLUMNS 
                WHERE TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION
            """
            self.cursor.execute(schema_query, (table_name,))
            columns = self.cursor.fetchall()
            
            schema = {
                'columns': {},
                'required_fields': [],
                'optional_fields': []
            }
            
            for col in columns:
                col_name = col.COLUMN_NAME
                schema['columns'][col_name] = {
                    'type': col.DATA_TYPE,
                    'nullable': col.IS_NULLABLE == 'YES',
                    'default': col.COLUMN_DEFAULT
                }
                
                if col.IS_NULLABLE == 'NO' and not col.COLUMN_DEFAULT:
                    schema['required_fields'].append(col_name)
                else:
                    schema['optional_fields'].append(col_name)
            
            self.schema_cache[table_name] = schema
            return schema
            
        except Exception as e:
            logging.error(f"Error getting schema for table {table_name}: {e}")
            return {}

    def validate_data(self, table_name: str, data: Dict) -> Tuple[bool, List[str]]:
        """Validate data against table schema"""
        errors = []
        schema = self.get_table_schema(table_name)
        
        if not schema:
            errors.append(f"Schema not found for table {table_name}")
            return False, errors
        
        # Check required fields
        required_fields = schema.get('required_fields', [])
        for field in required_fields:
            if field not in data or data[field] is None or data[field] == '':
                errors.append(f"Required field '{field}' is missing or empty")
        
        # Validate field types and constraints
        for field, value in data.items():
            if field in schema.get('columns', {}):
                col_info = schema['columns'][field]
                
                # Type validation
                if not self._validate_field_type(field, value, col_info['type']):
                    errors.append(f"Invalid type for field '{field}'")
                
                # Pattern validation
                if isinstance(value, str) and not self._validate_field_pattern(field, value):
                    errors.append(f"Invalid pattern for field '{field}'")
        
        return len(errors) == 0, errors

    def _validate_field_type(self, field_name: str, value: Any, db_type: str) -> bool:
        """Validate field type against database type"""
        if value is None:
            return True
            
        try:
            db_type = db_type.lower()
            
            if db_type in ['int', 'integer', 'smallint']:
                int(value)
                return abs(int(value)) <= FIELD_VALIDATION['max_int_value']
            elif db_type in ['bigint']:
                int(value)
                return abs(int(value)) <= FIELD_VALIDATION['max_bigint_value']
            elif db_type in ['float', 'real', 'decimal', 'numeric']:
                float(value)
                return True
            elif db_type in ['varchar', 'nvarchar', 'text', 'ntext']:
                return len(str(value)) <= FIELD_VALIDATION['max_string_length']
            elif db_type in ['bit']:
                return value in [0, 1, True, False, '0', '1']
            elif db_type in ['datetime', 'datetime2', 'date', 'time']:
                # Basic datetime validation - can be enhanced
                return True
            else:
                return True  # Unknown type, assume valid
                
        except (ValueError, TypeError):
            return False

    def _validate_field_pattern(self, field_name: str, value: str) -> bool:
        """Validate field patterns (hostname, IP, MAC, etc.)"""
        field_lower = field_name.lower()
        
        if 'hostname' in field_lower:
            return re.match(FIELD_VALIDATION['hostname_pattern'], value) is not None
        elif 'ip' in field_lower and 'address' in field_lower:
            return re.match(FIELD_VALIDATION['ip_pattern'], value) is not None
        elif 'mac' in field_lower:
            return re.match(FIELD_VALIDATION['mac_pattern'], value) is not None
        
        return True  # No specific pattern required

    def build_insert_query(self, table_name: str, data: Dict) -> Tuple[str, List]:
        """Dynamically build INSERT query based on available data"""
        schema = self.get_table_schema(table_name)
        
        # Filter data to only include valid columns
        valid_columns = schema.get('columns', {}).keys() if schema else data.keys()
        filtered_data = {k: v for k, v in data.items() if k in valid_columns}
        
        # Add auto-generated fields if not provided
        auto_fields = schema.get('auto_fields', {})
        for field, default_value in auto_fields.items():
            if field not in filtered_data or filtered_data[field] is None:
                filtered_data[field] = default_value
        
        if not filtered_data:
            raise ValueError("No valid data to insert")
        
        # Build query
        columns = list(filtered_data.keys())
        placeholders = []
        values = []
        
        for col in columns:
            value = filtered_data[col]
            if isinstance(value, str) and value.upper().startswith(('GETDATE()', 'NEWID()', 'NULL')):
                # SQL function, not a parameter
                placeholders.append(value)
            else:
                placeholders.append('?')
                values.append(value)
        
        query = f"""
            INSERT INTO {table_name} ({', '.join(columns)})
            VALUES ({', '.join(placeholders)})
        """
        
        return query, values

    def build_update_query(self, table_name: str, data: Dict, where_clause: str, where_params: List = None) -> Tuple[str, List]:
        """Dynamically build UPDATE query"""
        schema = self.get_table_schema(table_name)
        
        # Filter data to only include valid columns
        valid_columns = schema.get('columns', {}).keys() if schema else data.keys()
        filtered_data = {k: v for k, v in data.items() if k in valid_columns}
        
        if not filtered_data:
            raise ValueError("No valid data to update")
        
        # Build SET clause
        set_clauses = []
        values = []
        
        for col, value in filtered_data.items():
            if isinstance(value, str) and value.upper().startswith(('GETDATE()', 'NEWID()', 'NULL')):
                set_clauses.append(f"{col} = {value}")
            else:
                set_clauses.append(f"{col} = ?")
                values.append(value)
        
        query = f"""
            UPDATE {table_name} 
            SET {', '.join(set_clauses)}
            WHERE {where_clause}
        """
        
        # Add WHERE parameters
        if where_params:
            values.extend(where_params)
        
        return query, values

    def insert_data(self, table_name: str, data: Dict) -> bool:
        """Insert data with dynamic query building and validation"""
        try:
            if not self.check_connection():
                return False
            
            # Validate data
            is_valid, errors = self.validate_data(table_name, data)
            if not is_valid:
                logging.error(f"Data validation failed for {table_name}: {errors}")
                return False
            
            # Build and execute query
            query, params = self.build_insert_query(table_name, data)
            
            logging.debug(f"Executing INSERT: {query}")
            logging.debug(f"Parameters: {params}")
            
            self.cursor.execute(query, params)
            
            if not self.in_transaction:
                self.conn.commit()
            
            logging.info(f"Successfully inserted data into {table_name}")
            return True
            
        except Exception as e:
            logging.error(f"Error inserting data into {table_name}: {e}")
            logging.error(f"Data: {data}")
            if not self.in_transaction:
                try:
                    self.conn.rollback()
                except:
                    pass
            return False

    def update_data(self, table_name: str, data: Dict, where_clause: str, where_params: List = None) -> bool:
        """Update data with dynamic query building"""
        try:
            if not self.check_connection():
                return False
            
            # Build and execute query
            query, params = self.build_update_query(table_name, data, where_clause, where_params)
            
            logging.debug(f"Executing UPDATE: {query}")
            logging.debug(f"Parameters: {params}")
            
            self.cursor.execute(query, params)
            
            if not self.in_transaction:
                self.conn.commit()
            
            rows_affected = self.cursor.rowcount
            logging.info(f"Successfully updated {rows_affected} rows in {table_name}")
            return True
            
        except Exception as e:
            logging.error(f"Error updating data in {table_name}: {e}")
            if not self.in_transaction:
                try:
                    self.conn.rollback()
                except:
                    pass
            return False

    def execute_query(self, query: str, params=None):
        """Execute raw query with parameters"""
        try:
            if not self.check_connection():
                return None
                
            # Clear any pending results
            try:
                while self.cursor.nextset():
                    pass
            except:
                pass
                
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
                
            if not self.in_transaction and self.conn:
                self.conn.commit()
                
            return self.cursor
            
        except Exception as e:
            logging.error(f"Error executing query: {e}")
            logging.error(f"Query: {query}")
            logging.error(f"Params: {params}")
            
            if not self.in_transaction and self.conn:
                try:
                    self.conn.rollback()
                except:
                    pass
            return None

    def begin_transaction(self):
        """Begin database transaction"""
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

    def close(self):
        """Close database connection"""
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
        """Destructor"""
        try:
            self.close()
        except:
            pass