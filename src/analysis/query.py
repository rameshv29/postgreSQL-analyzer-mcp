"""
Functions for analyzing SQL queries and extracting information from them.
"""
from typing import List, Dict, Any, Tuple
import re
from db.connector import PostgresConnector
from db.queries import TABLE_STATS_QUERY, INDEX_INFO_QUERY, SCHEMA_INFO_QUERY

def extract_tables_from_query(query: str) -> List[str]:
    """
    Extract table names from a SQL query using regex
    
    Args:
        query: SQL query to analyze
        
    Returns:
        List of table names found in the query
    """
    query_lower = query.lower()
    tables = []
    
    try:
        # Extract table names from FROM clause
        if " from " in query_lower:
            from_parts = query_lower.split(" from ")[1]
            # Handle WHERE, GROUP BY, ORDER BY, etc.
            for clause in [" where ", " group by ", " order by ", " having ", " limit ", " offset "]:
                if clause in from_parts:
                    from_parts = from_parts.split(clause)[0]
            
            # Handle JOINs in FROM clause
            if " join " in from_parts:
                join_parts = from_parts.split(" join ")
                main_tables = join_parts[0].strip().split(",")
                for table_raw in main_tables:
                    table = table_raw.strip().split(" ")[-1]  # Get the alias or table name
                    if table and table not in tables:
                        tables.append(table)
                
                # Process JOIN parts
                for join_part in join_parts[1:]:
                    if " on " in join_part:
                        table = join_part.split(" on ")[0].strip().split(" ")[-1]
                    else:
                        table = join_part.strip().split(" ")[0]
                    
                    if table and table not in tables:
                        tables.append(table)
            else:
                # Simple FROM without JOINs
                table_parts = from_parts.split(",")
                for table_raw in table_parts:
                    parts = table_raw.strip().split(" ")
                    table = parts[0]  # Get the table name
                    if table and table not in tables:
                        tables.append(table)
    except Exception as e:
        print(f"Error extracting tables from query: {str(e)}")
    
    return tables

def get_table_statistics(connector: PostgresConnector, tables: List[str]) -> List[Dict[str, Any]]:
    """
    Get statistics for the specified tables
    
    Args:
        connector: PostgresConnector instance with active connection
        tables: List of table names to get statistics for
        
    Returns:
        List of dictionaries with table statistics
    """
    if not tables:
        return []
        
    placeholders = ", ".join(["%s" for _ in tables])
    query = TABLE_STATS_QUERY.format(placeholders)
    
    return connector.execute_query(query, tables)

def get_index_information(connector: PostgresConnector, tables: List[str]) -> List[Dict[str, Any]]:
    """
    Get index information for the specified tables
    
    Args:
        connector: PostgresConnector instance with active connection
        tables: List of table names to get index information for
        
    Returns:
        List of dictionaries with index information
    """
    if not tables:
        return []
        
    placeholders = ", ".join(["%s" for _ in tables])
    query = INDEX_INFO_QUERY.format(placeholders)
    
    return connector.execute_query(query, tables)

def get_schema_information(connector: PostgresConnector, tables: List[str]) -> List[Dict[str, Any]]:
    """
    Get schema information for the specified tables
    
    Args:
        connector: PostgresConnector instance with active connection
        tables: List of table names to get schema information for
        
    Returns:
        List of dictionaries with schema information
    """
    if not tables:
        return []
        
    placeholders = ", ".join(["%s" for _ in tables])
    query = SCHEMA_INFO_QUERY.format(placeholders)
    
    return connector.execute_query(query, tables)

def format_query_analysis_response(
    query: str,
    plan_json: Dict[str, Any],
    tables_involved: List[str],
    table_stats: List[Dict[str, Any]],
    schema_info: List[Dict[str, Any]],
    index_info: List[Dict[str, Any]],
    patterns: List[Dict[str, Any]],
    anti_patterns: List[Dict[str, Any]],
    complexity: Dict[str, Any]
) -> str:
    """
    Format query analysis results as a markdown response
    
    Args:
        query: The original SQL query
        plan_json: The execution plan JSON
        tables_involved: List of tables involved in the query
        table_stats: Table statistics
        schema_info: Schema information
        index_info: Index information
        patterns: Detected query patterns
        anti_patterns: Detected query anti-patterns
        complexity: Query complexity metrics
        
    Returns:
        Formatted markdown string with analysis
    """
    # Extract key metrics
    planning_time = plan_json.get('Planning Time', 0)
    execution_time = plan_json.get('Execution Time', 0)
    total_time = planning_time + execution_time
    
    # Format the response
    response = "## Query Analysis\n\n"
    
    # Add query complexity analysis
    response += "### Query Complexity Analysis\n"
    response += f"- **Complexity Score**: {complexity['complexity_score']}\n"
    response += f"- **Join Count**: {complexity['join_count']}\n"
    response += f"- **Subquery Count**: {complexity['subquery_count']}\n"
    response += f"- **Aggregation Count**: {complexity['aggregation_count']}\n"
    
    if complexity['warnings']:
        response += "- **Warnings**:\n"
        for warning in complexity['warnings']:
            response += f"  - {warning}\n"
    response += "\n"
    
    # Add execution metrics
    response += "### Execution Metrics\n"
    response += f"- **Total Time**: {total_time:.2f}ms\n"
    response += f"- **Planning Time**: {planning_time:.2f}ms\n"
    response += f"- **Execution Time**: {execution_time:.2f}ms\n\n"
    
    # Add plan analysis
    response += "### Plan Analysis\n"
    response += f"- **Plan Type**: {plan_json.get('Plan', {}).get('Node Type', 'Unknown')}\n"
    response += f"- **Estimated Cost**: {plan_json.get('Plan', {}).get('Total Cost', 0)}\n"
    response += f"- **Estimated Rows**: {plan_json.get('Plan', {}).get('Plan Rows', 0)}\n"
    response += f"- **Actual Rows**: {plan_json.get('Plan', {}).get('Actual Rows', 'N/A')}\n\n"
    
    # Add schema information
    response += "### Tables and Columns\n\n"
    for table in tables_involved:
        table_columns = [col for col in schema_info if col.get('table_name') == table]
        if table_columns:
            response += f"**{table}**:\n"
            for col in table_columns:
                nullable = "NULL" if col.get('is_nullable') == 'YES' else "NOT NULL"
                response += f"- {col.get('column_name')} ({col.get('data_type')}, {nullable})\n"
            response += "\n"
    
    # Add index information
    response += "### Index Information\n\n"
    for table in tables_involved:
        table_indexes = [idx for idx in index_info if idx.get('table_name') == table]
        if table_indexes:
            response += f"**{table}**:\n"
            for idx in table_indexes:
                response += f"- {idx.get('index_name')}: {idx.get('index_definition')}\n"
                response += f"  - Scans: {idx.get('index_scans', 0)}\n"
            response += "\n"
        else:
            response += f"**{table}**: No indexes found\n\n"
    
    # Add identified issues
    response += "### Identified Issues\n\n"
    if patterns:
        for pattern in patterns:
            response += f"- {pattern['description']} (Severity: {pattern['severity']})\n"
    
    if anti_patterns:
        for issue in anti_patterns:
            response += f"- {issue['issue']}\n"
            response += f"  - Suggestion: {issue['suggestion']}\n"
    
    if not patterns and not anti_patterns:
        response += "- No significant issues detected in the execution plan\n"
    
    response += "\n"
    
    # Add recommendations section for the model to fill
    response += "### Recommendations\n\n"
    # This section will be filled by the model based on the analysis data
    
    # Add execution plan for reference
    response += "### Execution Plan\n"
    response += "```json\n"
    import json
    response += json.dumps(plan_json, indent=2)
    response += "\n```\n"
    
    return response