"""
Functions for analyzing database structure.
"""
from typing import Dict, List, Any
from db.connector import PostgresConnector
from db.queries import TABLES_QUERY, COLUMNS_QUERY, INDEXES_QUERY, FOREIGN_KEYS_QUERY

def get_database_structure(connector: PostgresConnector) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get comprehensive database structure information
    
    Args:
        connector: PostgresConnector instance with active connection
        
    Returns:
        Dictionary containing tables, columns, indexes, and foreign keys
    """
    # Get tables
    tables = connector.execute_query(TABLES_QUERY)
    
    # Get columns
    columns = connector.execute_query(COLUMNS_QUERY)
    
    # Get indexes
    indexes = connector.execute_query(INDEXES_QUERY)
    
    # Get foreign keys
    foreign_keys = connector.execute_query(FOREIGN_KEYS_QUERY)
    
    # Organize the data
    db_structure = {
        "tables": tables,
        "columns": columns,
        "indexes": indexes,
        "foreign_keys": foreign_keys
    }
    
    return db_structure

def organize_db_structure_by_table(db_structure: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    """
    Organize database structure by table for easier analysis
    
    Args:
        db_structure: Database structure from get_database_structure()
        
    Returns:
        Dictionary with tables as keys and their details as values
    """
    tables_dict = {}
    
    # Process tables
    for table in db_structure["tables"]:
        table_key = f"{table['table_schema']}.{table['table_name']}"
        tables_dict[table_key] = {
            "schema": table["table_schema"],
            "name": table["table_name"],
            "size_bytes": table["table_size_bytes"],
            "total_size_bytes": table["total_size_bytes"],
            "estimated_row_count": table["estimated_row_count"],
            "description": table["table_description"],
            "columns": [],
            "indexes": [],
            "foreign_keys": []
        }
    
    # Add columns to their tables
    for column in db_structure["columns"]:
        table_key = f"{column['table_schema']}.{column['table_name']}"
        if table_key in tables_dict:
            tables_dict[table_key]["columns"].append({
                "name": column["column_name"],
                "data_type": column["data_type"],
                "max_length": column["character_maximum_length"],
                "nullable": column["is_nullable"],
                "default": column["column_default"],
                "description": column["column_description"]
            })
    
    # Add indexes to their tables
    for index in db_structure["indexes"]:
        table_key = f"{index['table_schema']}.{index['table_name']}"
        if table_key in tables_dict:
            tables_dict[table_key]["indexes"].append({
                "name": index["index_name"],
                "definition": index["index_definition"],
                "scans": index["index_scans"],
                "tuples_read": index["tuples_read"],
                "tuples_fetched": index["tuples_fetched"],
                "size_bytes": index["index_size_bytes"]
            })
    
    # Add foreign keys to their tables
    for fk in db_structure["foreign_keys"]:
        table_key = f"{fk['table_schema']}.{fk['table_name']}"
        if table_key in tables_dict:
            tables_dict[table_key]["foreign_keys"].append({
                "column": fk["column_name"],
                "references_table": f"{fk['foreign_table_schema']}.{fk['foreign_table_name']}",
                "references_column": fk["foreign_column_name"]
            })
    
    return tables_dict

def find_tables_without_indexes(tables_dict: Dict[str, Dict[str, Any]]) -> List[str]:
    """Find tables that have no indexes defined"""
    return [table_key for table_key, table_info in tables_dict.items() if not table_info["indexes"]]

def find_tables_without_primary_keys(tables_dict: Dict[str, Dict[str, Any]]) -> List[str]:
    """Find tables that have no primary key defined"""
    tables_without_pk = []
    
    for table_key, table_info in tables_dict.items():
        has_pk = False
        for idx in table_info["indexes"]:
            if "PRIMARY KEY" in idx["definition"]:
                has_pk = True
                break
        
        if not has_pk:
            tables_without_pk.append(table_key)
    
    return tables_without_pk

def find_large_tables(tables_dict: Dict[str, Dict[str, Any]], min_rows: int = 10000) -> List[Dict[str, Any]]:
    """Find tables with more than min_rows rows"""
    large_tables = []
    
    for table_key, table_info in tables_dict.items():
        if table_info["estimated_row_count"] > min_rows:
            large_tables.append({
                "name": table_key,
                "rows": table_info["estimated_row_count"],
                "size": table_info["total_size_bytes"]
            })
    
    return sorted(large_tables, key=lambda x: x["rows"], reverse=True)

def analyze_database_structure_for_response(db_structure: Dict[str, List[Dict[str, Any]]]) -> str:
    """
    Analyze database structure and format as a markdown response
    
    Args:
        db_structure: Database structure from get_database_structure()
        
    Returns:
        Formatted markdown string with analysis
    """
    # Organize by table for easier analysis
    tables_dict = organize_db_structure_by_table(db_structure)
    
    # Calculate some statistics for the model to use
    total_tables = len(db_structure["tables"])
    total_indexes = len(db_structure["indexes"])
    total_foreign_keys = len(db_structure["foreign_keys"])
    
    # Find tables without indexes
    tables_without_indexes = find_tables_without_indexes(tables_dict)
    
    # Find tables without primary keys
    tables_without_pk = find_tables_without_primary_keys(tables_dict)
    
    # Find large tables
    large_tables = find_large_tables(tables_dict)
    
    # Format the response
    response = "# Database Structure Analysis\n\n"
    
    response += "## Overview\n\n"
    response += f"- **Total Tables**: {total_tables}\n"
    response += f"- **Total Indexes**: {total_indexes}\n"
    response += f"- **Total Foreign Keys**: {total_foreign_keys}\n\n"
    
    # Add sections for potential issues
    if tables_without_indexes:
        response += "## Tables Without Indexes\n\n"
        for table in tables_without_indexes:
            response += f"- `{table}`\n"
        response += "\n"
    
    if tables_without_pk:
        response += "## Tables Without Primary Keys\n\n"
        for table in tables_without_pk:
            response += f"- `{table}`\n"
        response += "\n"
    
    if large_tables:
        response += "## Large Tables\n\n"
        response += "| Table | Estimated Rows | Size |\n"
        response += "| ----- | -------------- | ---- |\n"
        for table in large_tables:
            size_mb = table["size"] / (1024 * 1024)
            response += f"| `{table['name']}` | {table['rows']:,} | {size_mb:.2f} MB |\n"
        response += "\n"
    
    # Add detailed table information for the model to analyze
    response += "## Detailed Table Information\n\n"
    
    # Include only the first few tables to avoid overwhelming the response
    sample_tables = list(tables_dict.keys())[:5]
    for table_key in sample_tables:
        table_info = tables_dict[table_key]
        response += f"### {table_key}\n\n"
        response += f"- **Estimated Rows**: {table_info['estimated_row_count']:,}\n"
        response += f"- **Size**: {table_info['total_size_bytes'] / (1024 * 1024):.2f} MB\n"
        
        response += "\n**Columns**:\n\n"
        for column in table_info["columns"]:
            response += f"- `{column['name']}` ({column['data_type']})\n"
        
        response += "\n**Indexes**:\n\n"
        if table_info["indexes"]:
            for index in table_info["indexes"]:
                response += f"- `{index['name']}`: {index['definition']}\n"
                response += f"  - Scans: {index['scans']}\n"
        else:
            response += "- No indexes\n"
        
        response += "\n**Foreign Keys**:\n\n"
        if table_info["foreign_keys"]:
            for fk in table_info["foreign_keys"]:
                response += f"- `{fk['column']}` → `{fk['references_table']}`.`{fk['references_column']}`\n"
        else:
            response += "- No foreign keys\n"
        
        response += "\n"
    
    # Add note if there are more tables
    if len(tables_dict) > 5:
        response += f"*Note: Showing 5 out of {len(tables_dict)} tables. Use more specific tools to analyze individual tables.*\n\n"
    
    # The model will use the provided data to generate insights
    response += "## Analysis and Recommendations\n\n"
    # This section will be filled by the model based on the data provided
    
    return response