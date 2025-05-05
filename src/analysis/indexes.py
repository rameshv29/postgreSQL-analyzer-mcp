"""
Functions for analyzing and recommending indexes.
"""
from typing import List, Dict, Any, Tuple
import re
from db.connector import PostgresConnector
from db.queries import TABLE_STATS_FOR_INDEX_QUERY, COLUMNS_FOR_INDEX_QUERY, INDEXES_FOR_TABLE_QUERY

def extract_potential_indexes(query: str) -> List[Tuple[str, str]]:
    """
    Extract potential index candidates from a query
    
    Args:
        query: SQL query to analyze
        
    Returns:
        List of tuples (table_name, column_name) that could benefit from indexes
    """
    query_lower = query.lower()
    potential_indexes = []
    
    # Extract columns from WHERE clause
    if "where " in query_lower:
        where_clause = query_lower.split("where ")[1].split("group by")[0].split("order by")[0].split("limit")[0]
        conditions = where_clause.replace("and", ",").replace("or", ",").split(",")
        
        for condition in conditions:
            for operator in ["=", ">", "<", ">=", "<=", "like"]:
                if operator in condition:
                    parts = condition.split(operator)
                    if len(parts) >= 2:
                        column = parts[0].strip()
                        if "." in column:
                            table, col = column.split(".")
                            potential_indexes.append((table.strip(), col.strip()))
    
    # Extract columns from JOIN conditions
    join_parts = query_lower.split(" join ")
    for i in range(1, len(join_parts)):
        join_clause = join_parts[i]
        if " on " in join_clause:
            on_clause = join_clause.split(" on ")[1].split(" where ")[0].split(" group ")[0].split(" order ")[0]
            conditions = on_clause.replace("and", ",").replace("or", ",").split(",")
            
            for condition in conditions:
                if "=" in condition:
                    parts = condition.split("=")
                    if len(parts) >= 2:
                        for part in parts:
                            column = part.strip()
                            if "." in column:
                                table, col = column.split(".")
                                potential_indexes.append((table.strip(), col.strip()))
    
    # Extract columns from ORDER BY
    if "order by " in query_lower:
        order_clause = query_lower.split("order by ")[1].split("limit")[0]
        order_columns = order_clause.split(",")
        
        for column in order_columns:
            column = column.strip().split(" ")[0]  # Remove ASC/DESC
            if "." in column:
                table, col = column.split(".")
                potential_indexes.append((table.strip(), col.strip()))
    
    # Extract columns from GROUP BY
    if "group by " in query_lower:
        group_clause = query_lower.split("group by ")[1].split("having")[0].split("order")[0]
        group_columns = group_clause.split(",")
        
        for column in group_columns:
            column = column.strip()
            if "." in column:
                table, col = column.split(".")
                potential_indexes.append((table.strip(), col.strip()))
    
    return list(set(potential_indexes))  # Remove duplicates

def get_table_structure_for_index(connector: PostgresConnector, tables: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Get database structure information for index recommendations
    
    Args:
        connector: PostgresConnector instance with active connection
        tables: List of table names to analyze
        
    Returns:
        Dictionary with table structure information
    """
    db_structure = {}
    
    for table in tables:
        # Get table statistics
        table_stats = connector.execute_query(TABLE_STATS_FOR_INDEX_QUERY, [table])
        
        # Get column information
        columns = connector.execute_query(COLUMNS_FOR_INDEX_QUERY, [table])
        
        # Get existing indexes
        indexes = connector.execute_query(INDEXES_FOR_TABLE_QUERY, [table])
        
        db_structure[table] = {
            "statistics": table_stats[0] if table_stats else {},
            "columns": columns,
            "indexes": indexes
        }
    
    return db_structure

def check_existing_indexes(
    potential_indexes: List[Tuple[str, str]], 
    db_structure: Dict[str, Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Check which potential indexes already exist
    
    Args:
        potential_indexes: List of potential index candidates (table, column)
        db_structure: Database structure information
        
    Returns:
        Tuple of (existing_indexes, missing_indexes)
    """
    existing_indexes = []
    missing_indexes = []
    
    for table, column in potential_indexes:
        exists = False
        for idx_info in db_structure.get(table, {}).get("indexes", []):
            if column in idx_info.get("column_names", []):
                exists = True
                existing_indexes.append({
                    "table": table,
                    "column": column,
                    "index_name": idx_info.get("index_name"),
                    "is_unique": idx_info.get("is_unique"),
                    "is_primary": idx_info.get("is_primary"),
                    "index_type": idx_info.get("index_type")
                })
                break
        
        if not exists:
            missing_indexes.append({
                "table": table,
                "column": column
            })
    
    return existing_indexes, missing_indexes

def format_index_recommendations_response(
    query: str,
    plan_json: Dict[str, Any],
    db_structure: Dict[str, Dict[str, Any]],
    existing_indexes: List[Dict[str, Any]],
    missing_indexes: List[Dict[str, Any]]
) -> str:
    """
    Format index recommendations as a markdown response
    
    Args:
        query: The original SQL query
        plan_json: The execution plan JSON
        db_structure: Database structure information
        existing_indexes: List of existing indexes
        missing_indexes: List of missing indexes
        
    Returns:
        Formatted markdown string with recommendations
    """
    # Format the response
    response = "## Index Recommendations\n\n"
    
    # Add database structure context
    response += "### Database Structure Context\n\n"
    for table, info in db_structure.items():
        stats = info.get("statistics", {})
        response += f"**Table**: `{table}`\n"
        response += f"- **Rows**: {stats.get('row_count', 'Unknown')}\n"
        response += f"- **Sequential Scans**: {stats.get('seq_scan', 'Unknown')}\n"
        response += f"- **Index Scans**: {stats.get('idx_scan', 'Unknown')}\n"
        
        response += "- **Existing Indexes**:\n"
        for idx in info.get("indexes", []):
            idx_type = "PRIMARY KEY" if idx.get("is_primary") else ("UNIQUE" if idx.get("is_unique") else "INDEX")
            response += f"  - `{idx.get('index_name')}` ({idx_type}) on columns: {', '.join(idx.get('column_names', []))}\n"
        
        response += "\n"
    
    # Add execution plan summary
    response += "### Query Execution Plan Summary\n\n"
    response += f"- **Plan Type**: {plan_json.get('Plan', {}).get('Node Type', 'Unknown')}\n"
    response += f"- **Estimated Cost**: {plan_json.get('Plan', {}).get('Total Cost', 0)}\n"
    response += f"- **Estimated Rows**: {plan_json.get('Plan', {}).get('Plan Rows', 0)}\n\n"
    
    # Add index recommendations
    response += "### Recommended Indexes\n\n"
    
    if not missing_indexes:
        response += "All potential index candidates are already indexed. No new indexes recommended.\n\n"
    else:
        response += "Based on the query analysis and database structure, the following new indexes are recommended:\n\n"
        
        for idx in missing_indexes:
            response += f"- Add index on `{idx['table']}({idx['column']})`\n"
        
        response += "\n### SQL Commands for Recommended Indexes\n\n"
        response += "```sql\n"
        
        for idx in missing_indexes:
            response += f"CREATE INDEX idx_{idx['table']}_{idx['column']} ON {idx['table']}({idx['column']});\n"
        
        response += "```\n"
    
    # Add existing indexes information
    if existing_indexes:
        response += "\n### Existing Indexes Used by This Query\n\n"
        for idx in existing_indexes:
            idx_type = "PRIMARY KEY" if idx.get("is_primary") else ("UNIQUE" if idx.get("is_unique") else "INDEX")
            response += f"- Column `{idx['column']}` on table `{idx['table']}` is already indexed by `{idx['index_name']}` ({idx_type})\n"
    
    # Add note about testing
    response += "\n**Note**: Before creating indexes, test them in a staging environment and monitor their impact on both read and write performance.\n"
    
    # The model will use the provided data to generate additional insights
    response += "\n## Advanced Index Recommendations\n\n"
    # This section will be filled by the model based on the data provided
    
    return response