"""
Functions for detecting patterns and anti-patterns in SQL queries.
"""
from typing import List, Dict, Any

def detect_query_patterns(plan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect common query patterns and issues from the execution plan
    
    Args:
        plan_json: Execution plan JSON from EXPLAIN
        
    Returns:
        List of detected patterns with descriptions and severity
    """
    patterns = []
    plan = plan_json.get('Plan', {})
    
    # Check for sequential scans on large tables
    if plan.get('Node Type') == 'Seq Scan':
        table_name = plan.get('Relation Name')
        rows = plan.get('Plan Rows', 0)
        if rows > 1000:
            patterns.append({
                "type": "sequential_scan",
                "description": f"Sequential scan on table '{table_name}' with {rows} estimated rows",
                "severity": "high" if rows > 10000 else "medium"
            })
    
    # Check for nested loops with many iterations
    if plan.get('Node Type') == 'Nested Loop' and plan.get('Plan Rows', 0) > 1000:
        patterns.append({
            "type": "nested_loop",
            "description": f"Nested loop join with {plan.get('Plan Rows', 0)} estimated rows",
            "severity": "medium"
        })
    
    # Check for hash joins with high memory usage
    if plan.get('Node Type') == 'Hash Join' and plan.get('Peak Memory Usage', 0) > 1000:
        patterns.append({
            "type": "hash_join_memory",
            "description": f"High memory usage in hash join: {plan.get('Peak Memory Usage', 0)} KB",
            "severity": "medium"
        })
    
    # Recursively check child plans
    for child_key in ['Plans', 'Left Plan', 'Right Plan']:
        child_plans = plan.get(child_key)
        if isinstance(child_plans, list):
            for child_plan in child_plans:
                patterns.extend(detect_query_patterns({"Plan": child_plan}))
        elif isinstance(child_plans, dict):
            patterns.extend(detect_query_patterns({"Plan": child_plans}))
    
    return patterns

def detect_query_anti_patterns(query: str) -> List[Dict[str, Any]]:
    """
    Detect common anti-patterns in SQL queries
    
    Args:
        query: SQL query to analyze
        
    Returns:
        List of detected anti-patterns with descriptions and suggestions
    """
    query_lower = query.lower()
    issues = []
    
    # Check for SELECT *
    if "select *" in query_lower:
        issues.append({
            "issue": "Using SELECT * retrieves all columns, which can be inefficient",
            "suggestion": "Specify only the columns you need instead of using *",
            "example": query.replace("*", "column1, column2, column3")
        })
    
    # Check for missing LIMIT
    if "limit " not in query_lower and "offset " not in query_lower:
        issues.append({
            "issue": "Query does not have a LIMIT clause",
            "suggestion": "Add a LIMIT clause to prevent retrieving too many rows",
            "example": query + " LIMIT 100"
        })
    
    # Check for inefficient JOINs
    if " join " in query_lower and "using " not in query_lower and "on " not in query_lower:
        issues.append({
            "issue": "JOIN without explicit condition (potential cross join)",
            "suggestion": "Add explicit JOIN conditions using ON or USING clauses",
            "example": "Cannot suggest specific fix without understanding the data model"
        })
    
    # Check for inefficient WHERE clauses
    if "where " in query_lower:
        where_clause = query_lower.split("where ")[1].split("group by")[0].split("order by")[0].split("limit")[0]
        
        # Check for functions on indexed columns
        function_patterns = ["lower(", "upper(", "substr(", "to_char("]
        for pattern in function_patterns:
            if pattern in where_clause:
                issues.append({
                    "issue": f"Using function {pattern} in WHERE clause prevents index usage",
                    "suggestion": "Avoid using functions on indexed columns in WHERE clauses",
                    "example": "Consider restructuring the query or using functional indexes"
                })
        
        # Check for LIKE with leading wildcard
        if "like '%" in where_clause:
            issues.append({
                "issue": "LIKE with leading wildcard prevents efficient index usage",
                "suggestion": "Avoid LIKE queries with leading wildcards when possible",
                "example": "Consider full-text search instead of LIKE '%...%'"
            })
    
    # Check for inefficient subqueries
    if "(select" in query_lower:
        # Check for correlated subqueries
        if "where" in query_lower and "=" in query_lower:
            # This is a simplified check - in a real system, you'd need more sophisticated parsing
            issues.append({
                "issue": "Possible correlated subquery detected",
                "suggestion": "Consider replacing with JOIN operations where possible",
                "example": "Rewrite using JOIN instead of correlated subquery"
            })
    
    # Check for DISTINCT which can be expensive
    if "select distinct" in query_lower:
        issues.append({
            "issue": "DISTINCT can be expensive on large datasets",
            "suggestion": "Consider if DISTINCT is really necessary or if it can be handled in application code",
            "example": "If using DISTINCT to remove duplicates from JOINs, consider using appropriate JOIN types instead"
        })
    
    # Check for GROUP BY without indexes
    if "group by" in query_lower:
        issues.append({
            "issue": "GROUP BY operations are expensive without proper indexes",
            "suggestion": "Ensure columns in GROUP BY clause are indexed",
            "example": "CREATE INDEX idx_column ON table(column) for columns used in GROUP BY"
        })
    
    return issues

def validate_read_only_query(query: str) -> tuple[bool, str]:
    """
    Validate that a query is read-only and safe to execute
    
    Args:
        query: The query to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not query or not isinstance(query, str):
        return False, "Query must be a non-empty string"
    
    query_lower = query.lower().strip()
    
    # Allow SELECT, EXPLAIN, and SHOW queries
    if not (query_lower.startswith('select') or 
            query_lower.startswith('explain') or 
            query_lower.startswith('show')):
        return False, "Only SELECT, EXPLAIN, and SHOW queries are allowed for security reasons"
    
    # Block potentially dangerous operations even within allowed queries
    dangerous_patterns = [
        'insert', 'update', 'delete', 'drop', 'alter', 'create', 'truncate', 
        'grant', 'revoke', 'vacuum', 'reindex', 'cluster', 'reset', 'load',
        'copy', 'execute', 'prepare'
    ]
    
    # Remove 'set' from dangerous patterns since it's used in SHOW commands
    # But still check for potentially dangerous SET commands
    if query_lower.startswith('set ') and not query_lower.startswith('set transaction read only'):
        return False, "SET commands are not allowed except for setting transaction read only"
    
    # Check for dangerous operations in the query
    for pattern in dangerous_patterns:
        pattern_with_spaces = f' {pattern} '
        if pattern_with_spaces in f' {query_lower} ':
            return False, f"Potentially unsafe operation '{pattern}' detected in query"
    
    # Check for comments that might be hiding code
    if '--' in query_lower or '/*' in query_lower:
        # This is a simplified check - in a production system you might want
        # to parse comments more carefully to avoid false positives
        return False, "SQL comments are not allowed for security reasons"
    
    # Check for multiple statements
    if ';' in query_lower[:-1]:  # Allow semicolon at the end
        return False, "Multiple SQL statements are not allowed"
    
    return True, "Query is valid"