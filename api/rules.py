from flask import Blueprint, request, jsonify
from database.connection import DatabaseConnection

rules_api = Blueprint('rules_api', __name__)
db = DatabaseConnection()

@rules_api.route('/api/rules', methods=['GET'])
def get_rules():
    hostname = request.args.get('hostname')
    # Lấy rule chung
    query_common = """
        SELECT RuleID, RuleName, RuleType, Description, Severity, Action
        FROM Rules
        WHERE IsActive = 1 AND IsGlobal = 1
    """
    rules_common = db.execute_query(query_common)
    # Lấy rule riêng của agent
    rules_agent = []
    if hostname:
        query_agent = """
            SELECT r.RuleID, r.RuleName, r.RuleType, r.Description, r.Severity, r.Action
            FROM Rules r
            JOIN AgentRules ar ON r.RuleID = ar.RuleID
            WHERE ar.Hostname = ? AND ar.IsActive = 1 AND r.IsActive = 1
        """
        rules_agent = db.execute_query(query_agent, (hostname,))
    rules = list(rules_common or []) + list(rules_agent or [])
    return jsonify([{
        'RuleID': r[0],
        'RuleName': r[1],
        'RuleType': r[2],
        'Description': r[3],
        'Severity': r[4],
        'Action': r[5]
    } for r in rules])

@rules_api.route("/rules", methods=["POST"])
def create_rule():
    """Create a new rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        rules_db = RulesDB()
        if data.get("rule_type") == "cross_platform":
            result = rules_db.create_cross_platform_rule(data)
        else:
            result = rules_db.create_rule(data)
            
        if result:
            return jsonify({"message": "Rule created successfully"}), 201
        return jsonify({"error": "Failed to create rule"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500 