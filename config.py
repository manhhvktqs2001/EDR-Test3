# Backend Configuration File (config.py)
import logging
import os

# Database settings
DB_SETTINGS = {
    'connection_string': "Driver={ODBC Driver 17 for SQL Server};Server=MANH;Database=EDR_System;Trusted_Connection=yes;",
    'timeout': 30,
    'autocommit': True
}

# Server settings
SERVER_SETTINGS = {
    'host': '0.0.0.0',  # Listen on all interfaces
    'port': 5000,
    'debug': False,
    'threaded': True
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': logging.INFO,
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'server.log',
    'max_size_mb': 100,
    'backup_count': 5
}

# Database Table Schema Mapping - Dynamic field detection
DATABASE_SCHEMA = {
    'ProcessLogs': {
        'required_fields': ['Hostname', 'ProcessID', 'ProcessName'],
        'optional_fields': [
            'Time', 'ParentProcessID', 'CommandLine', 'ExecutablePath', 
            'UserName', 'CPUUsage', 'MemoryUsage', 'Hash'
        ],
        'auto_fields': {
            'Time': 'GETDATE()',  # Auto-generated if not provided
        },
        'field_types': {
            'ProcessID': 'int',
            'ParentProcessID': 'int', 
            'CPUUsage': 'float',
            'MemoryUsage': 'bigint',
            'Time': 'datetime',
            'Hostname': 'varchar',
            'ProcessName': 'varchar',
            'CommandLine': 'varchar',
            'ExecutablePath': 'varchar',
            'UserName': 'varchar',
            'Hash': 'varchar'
        }
    },
    'FileLogs': {
        'required_fields': ['Hostname', 'FileName', 'FilePath', 'EventType'],
        'optional_fields': [
            'Time', 'FileSize', 'FileHash', 'ProcessID', 'ProcessName'
        ],
        'auto_fields': {
            'Time': 'GETDATE()',
        },
        'field_types': {
            'ProcessID': 'int',
            'FileSize': 'bigint',
            'Time': 'datetime',
            'Hostname': 'varchar',
            'FileName': 'varchar',
            'FilePath': 'varchar',
            'EventType': 'varchar',
            'FileHash': 'varchar',
            'ProcessName': 'varchar'
        }
    },
    'NetworkLogs': {
        'required_fields': ['Hostname', 'ProcessID', 'ProcessName', 'Protocol'],
        'optional_fields': [
            'Time', 'LocalAddress', 'LocalPort', 'RemoteAddress', 
            'RemotePort', 'Direction'
        ],
        'auto_fields': {
            'Time': 'GETDATE()',
        },
        'field_types': {
            'ProcessID': 'int',
            'LocalPort': 'int',
            'RemotePort': 'int',
            'Time': 'datetime',
            'Hostname': 'varchar',
            'ProcessName': 'varchar',
            'Protocol': 'varchar',
            'LocalAddress': 'varchar',
            'RemoteAddress': 'varchar',
            'Direction': 'varchar'
        }
    },
    'Alerts': {
        'required_fields': ['Hostname', 'RuleID', 'AlertType', 'Severity', 'Title', 'Description'],
        'optional_fields': [
            'Time', 'Status', 'DetectionData', 'Action'
        ],
        'auto_fields': {
            'Time': 'GETDATE()',
            'Status': "'New'"
        },
        'field_types': {
            'RuleID': 'bigint',
            'Time': 'datetime',
            'Hostname': 'varchar',
            'AlertType': 'varchar',
            'Severity': 'varchar',
            'Status': 'varchar',
            'Title': 'varchar',
            'Description': 'varchar',
            'DetectionData': 'varchar',
            'Action': 'varchar'
        }
    },
    'Agents': {
        'required_fields': ['Hostname', 'OSType', 'OSVersion', 'AgentVersion'],
        'optional_fields': [
            'Architecture', 'IPAddress', 'MACAddress', 'Status', 
            'IsActive', 'FirstSeen', 'LastHeartbeat', 'LastSeen'
        ],
        'auto_fields': {
            'Status': "'Online'",
            'IsActive': '1',
            'FirstSeen': 'GETDATE()',
            'LastHeartbeat': 'GETDATE()',
            'LastSeen': 'GETDATE()'
        },
        'field_types': {
            'IsActive': 'bit',
            'FirstSeen': 'datetime',
            'LastHeartbeat': 'datetime',
            'LastSeen': 'datetime',
            'Hostname': 'varchar',
            'OSType': 'varchar',
            'OSVersion': 'varchar',
            'Architecture': 'varchar',
            'IPAddress': 'varchar',
            'MACAddress': 'varchar',
            'AgentVersion': 'varchar',
            'Status': 'varchar'
        }
    }
}

# Rule Engine Configuration
RULE_ENGINE_CONFIG = {
    'refresh_interval': 60,  # seconds
    'max_rules_cache': 1000,
    'rule_types': ['Process', 'File', 'Network'],
    'severity_levels': ['Low', 'Medium', 'High', 'Critical'],
    'actions': ['Alert', 'AlertAndBlock', 'Block', 'Monitor']
}

# Alert Configuration
ALERT_CONFIG = {
    'max_alerts_per_minute': 100,
    'alert_retention_days': 30,
    'default_status': 'New',
    'notification_timeout': 15
}

# Performance Settings
PERFORMANCE_SETTINGS = {
    'max_concurrent_agents': 1000,
    'log_batch_size': 50,
    'database_timeout': 30,
    'socket_timeout': 60,
    'ping_interval': 25,
    'ping_timeout': 60
}

# Field Validation Rules
FIELD_VALIDATION = {
    'hostname_pattern': r'^[a-zA-Z0-9\-._]+$',
    'ip_pattern': r'^(\d{1,3}\.){3}\d{1,3}$',
    'mac_pattern': r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
    'max_string_length': 8000,
    'max_int_value': 2147483647,
    'max_bigint_value': 9223372036854775807
}

# Environment specific settings
ENVIRONMENT = os.getenv('EDR_ENVIRONMENT', 'development')

if ENVIRONMENT == 'production':
    LOGGING_CONFIG['level'] = logging.WARNING
    SERVER_SETTINGS['debug'] = False
elif ENVIRONMENT == 'development':
    LOGGING_CONFIG['level'] = logging.DEBUG
    SERVER_SETTINGS['debug'] = True