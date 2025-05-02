from mcp.server.fastmcp import Context, FastMCP
from contextlib import asynccontextmanager
import json
import re
import psycopg2
import boto3
import base64
import os
import time
from datetime import datetime
from typing import List, Dict, Any, Optional

# PostgresConnector class implementation
class PostgresConnector:
    def __init__(self, secret_name=None, region_name=None, host=None, port=None, 
                 dbname=None, user=None, password=None):
        self.secret_name = secret_name
        self.region_name = region_name
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.password = password
        self.conn = None
        self.read_only = True  # Default to read-only mode
        
    def connect(self):
        """Connect to PostgreSQL database using either AWS Secrets or direct credentials"""
        try:
            if self.secret_name and self.region_name:
                # Get credentials from AWS Secrets Manager
                session = boto3.session.Session()
                client = session.client(
                    service_name='secretsmanager',
                    region_name=self.region_name
                )
                
                get_secret_value_response = client.get_secret_value(
                    SecretId=self.secret_name
                )
                
                if 'SecretString' in get_secret_value_response:
                    secret = json.loads(get_secret_value_response['SecretString'])
                    self.host = secret.get('host')
                    self.port = secret.get('port', 5432)
                    self.dbname = secret.get('dbname')
                    self.user = secret.get('username')
                    self.password = secret.get('password')
                else:
                    decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
                    secret = json.loads(decoded_binary_secret)
                    self.host = secret.get('host')
                    self.port = secret.get('port', 5432)
                    self.dbname = secret.get('dbname')
                    self.user = secret.get('username')
                    self.password = secret.get('password')
            elif not all([self.host, self.dbname, self.user, self.password]):
                # If direct credentials are not provided and no secret name, we can't connect
                print("Error: Either AWS Secrets Manager details or direct database credentials must be provided")
                return False
            
            # Connect to the database
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port or 5432,
                dbname=self.dbname,
                user=self.user,
                password=self.password
            )
            
            # Set session to read-only mode for safety
            if self.read_only:
                with self.conn.cursor() as cursor:
                    cursor.execute("SET TRANSACTION READ ONLY")
                    cursor.execute("SET statement_timeout = '30s'")  # 30-second timeout
            
            print(f"Connected to PostgreSQL database: {self.dbname} at {self.host}")
            return True
        except Exception as e:
            print(f"Error connecting to database: {str(e)}")
            return False
    
    def disconnect(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None
            print("Database connection closed")
    
    def execute_query(self, query, params=None):
        """Execute a query and return results as a list of dictionaries"""
        if not self.conn:
            print("No database connection. Call connect() first.")
            return []
        
        try:
            with self.conn.cursor() as cursor:
                # For safety, check if this is a potentially dangerous operation
                if self.read_only:
                    query_lower = query.lower().strip()
                    dangerous_operations = [
                        'insert', 'update', 'delete', 'drop', 'alter', 'create', 'truncate', 
                        'grant', 'revoke', 'vacuum', 'reindex', 'cluster', 'reset', 'load',
                        'copy'
                    ]
                    
                    # Check if query starts with any dangerous operation
                    for op in dangerous_operations:
                        if query_lower.startswith(op):
                            print(f"Error: Write operation '{op}' attempted in read-only mode")
                            return []
                
                cursor.execute(query, params)
                
                # For SELECT queries, return results
                if cursor.description:
                    columns = [desc[0] for desc in cursor.description]
                    results = []
                    for row in cursor.fetchall():
                        results.append(dict(zip(columns, row)))
                    return results
                
                # For non-SELECT queries, commit and return empty list
                self.conn.commit()
                return []
        except Exception as e:
            self.conn.rollback()
            print(f"Error executing query: {str(e)}")
            return []

    def analyze_query_complexity(self, query):
        """
        Analyze query complexity and potential resource impact
        
        Args:
            query (str): SQL query to analyze
        
        Returns:
            dict: Complexity metrics
        """
        query_lower = query.lower()
        complexity_score = 0
        warnings = []
        
        # Check for joins
        join_count = sum(1 for join_type in ['join', 'inner join', 'left join', 'right join', 'full join'] 
                        if join_type in query_lower)
        complexity_score += join_count * 2
        if join_count > 3:
            warnings.append(f"Query contains {join_count} joins - consider simplifying")
        
        # Check for subqueries
        subquery_count = query_lower.count('(select')
        complexity_score += subquery_count * 3
        if subquery_count > 2:
            warnings.append(f"Query contains {subquery_count} subqueries - consider restructuring")
        
        # Check for aggregations
        agg_functions = ['count(', 'sum(', 'avg(', 'max(', 'min(']
        agg_count = sum(query_lower.count(func) for func in agg_functions)
        complexity_score += agg_count
        
        # Check for window functions
        if 'over(' in query_lower or 'partition by' in query_lower:
            complexity_score += 3
            warnings.append("Query uses window functions - monitor performance")
        
        # Check for complex WHERE conditions
        where_pos = query_lower.find('where')
        if where_pos != -1:
            where_clause = query_lower[where_pos:]
            and_count = where_clause.count(' and ')
            or_count = where_clause.count(' or ')
            complexity_score += (and_count + or_count)
            if (and_count + or_count) > 5:
                warnings.append(f"Complex WHERE clause with {and_count + or_count} conditions")
        
        return {
            'complexity_score': complexity_score,
            'warnings': warnings,
            'join_count': join_count,
            'subquery_count': subquery_count,
            'aggregation_count': agg_count
        }

# Initialize FastMCP app
mcp = FastMCP(
    "PostgreSQL Performance Analyzer", 
    instructions="""
    This MCP server helps you optimize PostgreSQL database performance by:
    - Identifying slow-running queries
    - Analyzing query execution plans
    - Recommending indexes
    - Suggesting query rewrites
    - Analyzing database structure
    
    IMPORTANT: This is a READ-ONLY tool. All operations are performed in read-only mode
    for security reasons. No database modifications will be made.
    
    You must provide an AWS Secrets Manager secret name containing your database credentials
    when using any of the tools. The secret should contain the following keys:
    - host: Database hostname
    - port: Database port (usually 5432)
    - dbname: Database name
    - username: Database username
    - password: Database password
    
    Example usage:
    analyze_database_structure(secret_name="my-postgres-db-credentials", region_name="us-west-2")
    """
)

# Dictionary to store database connections for each context
db_contexts = {}

@asynccontextmanager
async def server_lifespan(server: FastMCP):
    """Manage application lifecycle for the MCP server"""
    try:
        print("Starting PostgreSQL Performance Analyzer MCP Server")
        yield
    finally:
        # Clean up any remaining database connections
        for context_id, connector in db_contexts.items():
            if connector:
                connector.disconnect()
                print(f"Closed database connection for context {context_id}")

# Set the lifespan manager
mcp.lifespan = server_lifespan

# Helper functions for database structure analysis
def get_database_structure(connector):
    """Get comprehensive database structure information"""
    # Get tables
    tables_query = """
        SELECT 
            t.table_schema,
            t.table_name,
            pg_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name)) as table_size_bytes,
            pg_total_relation_size(quote_ident(t.table_schema) || '.' || quote_ident(t.table_name)) as total_size_bytes,
            (SELECT count(*) FROM information_schema.columns c WHERE c.table_schema = t.table_schema AND c.table_name = t.table_name) as column_count,
            COALESCE(obj_description(
                (quote_ident(t.table_schema) || '.' || quote_ident(t.table_name))::regclass::oid, 
                'pg_class'
            ), '') as table_description,
            s.n_live_tup as estimated_row_count
        FROM 
            information_schema.tables t
        JOIN
            pg_stat_user_tables s ON t.table_schema = s.schemaname AND t.table_name = s.relname
        WHERE 
            t.table_schema NOT IN ('pg_catalog', 'information_schema')
            AND t.table_type = 'BASE TABLE'
        ORDER BY 
            t.table_schema, t.table_name
    """
    tables = connector.execute_query(tables_query)
    
    # Get columns
    columns_query = """
        SELECT 
            c.table_schema,
            c.table_name,
            c.column_name,
            c.data_type,
            c.character_maximum_length,
            c.is_nullable,
            c.column_default,
            COALESCE(pg_catalog.col_description(
                format('%I.%I', c.table_schema, c.table_name)::regclass::oid, 
                c.ordinal_position
            ), '') as column_description
        FROM 
            information_schema.columns c
        WHERE 
            c.table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY 
            c.table_schema, c.table_name, c.ordinal_position
    """
    columns = connector.execute_query(columns_query)
    
    # Get indexes
    indexes_query = """
        SELECT
            schemaname as table_schema,
            relname as table_name,
            indexrelname as index_name,
            pg_get_indexdef(indexrelid) as index_definition,
            idx_scan as index_scans,
            idx_tup_read as tuples_read,
            idx_tup_fetch as tuples_fetched,
            pg_relation_size(indexrelid) as index_size_bytes
        FROM
            pg_stat_user_indexes
        WHERE
            schemaname NOT IN ('pg_catalog', 'information_schema')
        ORDER BY
            schemaname, relname, indexrelname
    """
    indexes = connector.execute_query(indexes_query)
    
    # Get foreign keys
    foreign_keys_query = """
        SELECT
            tc.table_schema,
            tc.table_name,
            kcu.column_name,
            ccu.table_schema AS foreign_table_schema,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM
            information_schema.table_constraints tc
        JOIN
            information_schema.key_column_usage kcu ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        JOIN
            information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name
            AND ccu.table_schema = tc.table_schema
        WHERE
            tc.constraint_type = 'FOREIGN KEY'
            AND tc.table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY
            tc.table_schema, tc.table_name
    """
    foreign_keys = connector.execute_query(foreign_keys_query)
    
    # Organize the data
    db_structure = {
        "tables": tables,
        "columns": columns,
        "indexes": indexes,
        "foreign_keys": foreign_keys
    }
    
    return db_structure

def organize_db_structure_by_table(db_structure):
    """Organize database structure by table for easier analysis"""
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

@mcp.tool()
async def analyze_database_structure(secret_name: str = None, region_name: str = "us-west-2", ctx: Context = None) -> str:
    """
    Analyze the database structure and provide insights on schema design, indexes, and potential optimizations.
    
    Args:
        secret_name: AWS Secrets Manager secret name containing database credentials (required)
        region_name: AWS region where the secret is stored (default: us-west-2)
    
    Returns:
        A comprehensive analysis of the database structure with optimization recommendations
    """
    context_id = getattr(ctx, 'id', "default") if ctx else "default"
    
    # Check if secret_name is provided
    if not secret_name:
        return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
    
    # Initialize connector with the provided secret name
    connector = PostgresConnector(
        secret_name=secret_name,
        region_name=region_name
    )
    
    if connector.connect():
        db_contexts[context_id] = connector
    else:
        return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
    
    try:
        # Get comprehensive database structure
        db_structure = get_database_structure(connector)
        
        # Organize by table for easier analysis
        tables_dict = organize_db_structure_by_table(db_structure)
        
        # Calculate some statistics for the model to use
        total_tables = len(db_structure["tables"])
        total_indexes = len(db_structure["indexes"])
        total_foreign_keys = len(db_structure["foreign_keys"])
        
        # Find tables without indexes
        tables_without_indexes = []
        large_tables = []
        tables_without_pk = []
        
        for table_key, table_info in tables_dict.items():
            if not table_info["indexes"]:
                tables_without_indexes.append(table_key)
            
            # Tables with more than 10,000 rows are considered large
            if table_info["estimated_row_count"] > 10000:
                large_tables.append({
                    "name": table_key,
                    "rows": table_info["estimated_row_count"],
                    "size": table_info["total_size_bytes"]
                })
            
            # Check for primary key
            has_pk = False
            for idx in table_info["indexes"]:
                if "PRIMARY KEY" in idx["definition"]:
                    has_pk = True
                    break
            
            if not has_pk:
                tables_without_pk.append(table_key)
        
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
            for table in sorted(large_tables, key=lambda x: x["rows"], reverse=True):
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
    except Exception as e:
        return f"Error analyzing database structure: {str(e)}"

@mcp.tool()
async def get_slow_queries(secret_name: str = None, region_name: str = "us-west-2", 
                          min_execution_time: int = 100, limit: int = 10, ctx: Context = None) -> str:
    """
    Identify slow-running queries in the database.
    
    Args:
        secret_name: AWS Secrets Manager secret name containing database credentials (required)
        region_name: AWS region where the secret is stored (default: us-west-2)
        min_execution_time: Minimum execution time in milliseconds (default: 100ms)
        limit: Maximum number of queries to return (default: 10)
    
    Returns:
        A list of slow queries with their execution statistics and analysis
    """
    context_id = getattr(ctx, 'id', "default") if ctx else "default"
    
    # Check if secret_name is provided
    if not secret_name:
        return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
    
    # Initialize connector with the provided secret name
    connector = PostgresConnector(
        secret_name=secret_name,
        region_name=region_name
    )
    
    if connector.connect():
        db_contexts[context_id] = connector
    else:
        return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
    
    try:
        # First check if pg_stat_statements extension is installed
        check_extension_query = """
            SELECT COUNT(*) as count FROM pg_extension WHERE extname = 'pg_stat_statements'
        """
        extension_result = connector.execute_query(check_extension_query)
        
        if not extension_result or extension_result[0]['count'] == 0:
            return """
                The pg_stat_statements extension is not installed. This extension is required to track query statistics.
                
                To install it, connect as a superuser and run:
                ```sql
                CREATE EXTENSION pg_stat_statements;
                ```
                
                Then add to postgresql.conf:
                ```
                shared_preload_libraries = 'pg_stat_statements'
                pg_stat_statements.track = all
                ```
                
                And restart the PostgreSQL server.
            """
        
        # Query to find slow queries from pg_stat_statements
        query = """
            SELECT 
                query,
                calls,
                total_exec_time / calls as avg_exec_time_ms,
                total_exec_time as total_time_ms,
                rows / calls as avg_rows,
                max_exec_time as max_time_ms,
                mean_exec_time as mean_time_ms,
                stddev_exec_time as stddev_time_ms,
                min_exec_time as min_time_ms
            FROM pg_stat_statements
            WHERE total_exec_time / calls >= %s
            ORDER BY avg_exec_time_ms DESC
            LIMIT %s
        """
        
        results = connector.execute_query(query, [min_execution_time, limit])
        
        if not results:
            return f"No queries found with execution time >= {min_execution_time}ms."
        
        # Format results as markdown
        response = f"## Slow Queries (Execution Time >= {min_execution_time}ms)\n\n"
        
        # Extract patterns and prepare data for model analysis
        query_patterns = {}
        total_execution_time = 0
        max_single_time = 0
        total_calls = 0
        
        for i, query_stat in enumerate(results, 1):
            response += f"### Query {i}\n"
            response += f"- **Average Execution Time**: {query_stat['avg_exec_time_ms']:.2f}ms\n"
            response += f"- **Total Execution Time**: {query_stat['total_time_ms']:.2f}ms\n"
            response += f"- **Calls**: {query_stat['calls']}\n"
            response += f"- **Average Rows**: {query_stat['avg_rows']}\n"
            response += f"- **Max Execution Time**: {query_stat['max_time_ms']:.2f}ms\n"
            response += f"- **Min Execution Time**: {query_stat['min_time_ms']:.2f}ms\n"
            response += f"- **Standard Deviation**: {query_stat['stddev_time_ms']:.2f}ms\n"
            response += f"- **SQL**: ```sql\n{query_stat['query']}\n```\n\n"
            
            # Analyze query complexity
            complexity = connector.analyze_query_complexity(query_stat['query'])
            response += "#### Complexity Analysis\n"
            response += f"- **Complexity Score**: {complexity['complexity_score']}\n"
            response += f"- **Join Count**: {complexity['join_count']}\n"
            response += f"- **Subquery Count**: {complexity['subquery_count']}\n"
            response += f"- **Aggregation Count**: {complexity['aggregation_count']}\n"
            
            if complexity['warnings']:
                response += "- **Warnings**:\n"
                for warning in complexity['warnings']:
                    response += f"  - {warning}\n"
            response += "\n"
            
            # Collect data for pattern analysis
            total_execution_time += query_stat['total_time_ms']
            total_calls += query_stat['calls']
            max_single_time = max(max_single_time, query_stat['max_time_ms'])
            
            # Categorize query by type (SELECT, INSERT, UPDATE, etc.)
            query_type = query_stat['query'].strip().upper().split(' ')[0]
            if query_type not in query_patterns:
                query_patterns[query_type] = 0
            query_patterns[query_type] += 1
        
        # Add summary section for model to provide insights
        response += "## Summary Analysis\n\n"
        response += f"- **Total Queries Analyzed**: {len(results)}\n"
        response += f"- **Total Execution Time**: {total_execution_time:.2f}ms\n"
        response += f"- **Total Query Calls**: {total_calls}\n"
        response += f"- **Query Type Distribution**: {', '.join([f'{k}: {v}' for k, v in query_patterns.items()])}\n\n"
        
        # The model will use this data to provide insights in the response
        response += "### Key Observations\n\n"
        # This section will be filled by the model based on the data provided
        
        return response
    except Exception as e:
        return f"Error retrieving slow queries: {str(e)}"

# Helper functions for query analysis
def extract_tables_from_query(query):
    """Extract table names from a SQL query using regex"""
    # This is a simplified approach - in reality, you'd use a SQL parser
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

def get_table_statistics(connector, tables):
    """Get statistics for the specified tables"""
    if not tables:
        return []
        
    placeholders = ", ".join(["%s" for _ in tables])
    query = f"""
        SELECT 
            schemaname, 
            relname as table_name, 
            n_live_tup as row_count,
            n_dead_tup as dead_tuples,
            seq_scan,
            idx_scan
        FROM pg_stat_user_tables
        WHERE relname IN ({placeholders})
    """
    
    return connector.execute_query(query, tables)

def get_index_information(connector, tables):
    """Get index information for the specified tables"""
    if not tables:
        return []
        
    placeholders = ", ".join(["%s" for _ in tables])
    query = f"""
        SELECT
            schemaname as table_schema,
            relname as table_name,
            indexrelname as index_name,
            pg_get_indexdef(indexrelid) as index_definition,
            idx_scan as index_scans,
            idx_tup_read as tuples_read,
            idx_tup_fetch as tuples_fetched
        FROM
            pg_stat_user_indexes
        WHERE
            relname IN ({placeholders})
        ORDER BY
            schemaname, relname, indexrelname
    """
    
    return connector.execute_query(query, tables)

def get_schema_information(connector, tables):
    """Get schema information for the specified tables"""
    if not tables:
        return []
        
    placeholders = ", ".join(["%s" for _ in tables])
    query = f"""
        SELECT 
            table_name, 
            column_name, 
            data_type,
            character_maximum_length,
            is_nullable,
            column_default
        FROM 
            information_schema.columns
        WHERE 
            table_name IN ({placeholders})
            AND table_schema = 'public'
        ORDER BY 
            table_name, 
            ordinal_position
    """
    
    return connector.execute_query(query, tables)

def detect_query_patterns(plan_json):
    """Detect common query patterns and issues from the execution plan"""
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

def detect_query_anti_patterns(query):
    """Detect common anti-patterns in SQL queries"""
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
    
    return issues

def extract_potential_indexes(query):
    """Extract potential index candidates from a query"""
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

@mcp.tool()
async def analyze_query(query: str, secret_name: str = None, region_name: str = "us-west-2", ctx: Context = None) -> str:
    """
    Analyze a SQL query and provide optimization recommendations.
    
    Args:
        query: The SQL query to analyze
        secret_name: AWS Secrets Manager secret name containing database credentials (required)
        region_name: AWS region where the secret is stored (default: us-west-2)
    
    Returns:
        Analysis of the query execution plan and optimization suggestions
    """
    context_id = getattr(ctx, 'id', "default") if ctx else "default"
    
    # Check if secret_name is provided
    if not secret_name:
        return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
    
    # Initialize connector with the provided secret name
    connector = PostgresConnector(
        secret_name=secret_name,
        region_name=region_name
    )
    
    if connector.connect():
        db_contexts[context_id] = connector
    else:
        return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
    
    try:
        # Clean the query before analysis
        query = query.strip()
        
        # Get the execution plan
        explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {query}"
        explain_results = connector.execute_query(explain_query)
        
        if not explain_results or not explain_results[0]:
            return "Failed to generate execution plan for the query. The EXPLAIN command returned no results."
        
        # Extract the plan JSON
        plan_json = None
        if 'QUERY PLAN' in explain_results[0]:
            query_plan = explain_results[0]['QUERY PLAN']
            if isinstance(query_plan, list) and len(query_plan) > 0:
                plan_json = query_plan[0]
            else:
                return f"Error: Unexpected EXPLAIN result structure: {query_plan}"
        else:
            # Try alternative formats
            if 'Plan' in explain_results[0]:
                plan_json = explain_results[0]
            else:
                return f"Error: Could not find query plan in EXPLAIN results: {explain_results[0]}"
        
        # Get estimated plan for comparison
        estimated_query = f"EXPLAIN (FORMAT JSON) {query}"
        estimated_results = connector.execute_query(estimated_query)
        estimated_plan = None
        
        if estimated_results and 'QUERY PLAN' in estimated_results[0]:
            estimated_plan = estimated_results[0]['QUERY PLAN'][0]
        else:
            # Use the actual plan as fallback
            estimated_plan = plan_json
        
        # Extract key metrics
        planning_time = plan_json.get('Planning Time', 0)
        execution_time = plan_json.get('Execution Time', 0)
        total_time = planning_time + execution_time
        
        # Get database structure information for tables involved in the query
        tables_involved = extract_tables_from_query(query)
        if not tables_involved:
            return "Could not identify any tables in the query. Please check the query syntax."
            
        table_stats = get_table_statistics(connector, tables_involved)
        schema_info = get_schema_information(connector, tables_involved)
        index_info = get_index_information(connector, tables_involved)
        
        # Detect query patterns and anti-patterns
        patterns = detect_query_patterns(plan_json)
        anti_patterns = detect_query_anti_patterns(query)
        
        # Analyze query complexity
        complexity = connector.analyze_query_complexity(query)
        
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
        response += json.dumps(plan_json, indent=2)
        response += "\n```\n"
        
        return response
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        return f"Error analyzing query: {str(e)}\n\nDetails:\n{error_details}"

@mcp.tool()
async def recommend_indexes(query: str, secret_name: str = None, region_name: str = "us-west-2", ctx: Context = None) -> str:
    """
    Recommend indexes for a given SQL query.
    
    Args:
        query: The SQL query to analyze for index recommendations
        secret_name: AWS Secrets Manager secret name containing database credentials (required)
        region_name: AWS region where the secret is stored (default: us-west-2)
    
    Returns:
        Recommended indexes to improve query performance
    """
    context_id = getattr(ctx, 'id', "default") if ctx else "default"
    
    # Check if secret_name is provided
    if not secret_name:
        return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
    
    # Initialize connector with the provided secret name
    connector = PostgresConnector(
        secret_name=secret_name,
        region_name=region_name
    )
    
    if connector.connect():
        db_contexts[context_id] = connector
    else:
        return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
    
    try:
        # First, analyze the database structure to understand the context
        tables_involved = extract_tables_from_query(query)
        db_structure = {}
        
        for table in tables_involved:
            # Get table statistics
            table_stats_query = """
                SELECT 
                    schemaname, 
                    relname as table_name, 
                    n_live_tup as row_count,
                    seq_scan,
                    seq_tup_read,
                    idx_scan,
                    idx_tup_fetch
                FROM pg_stat_user_tables
                WHERE relname = %s
            """
            table_stats = connector.execute_query(table_stats_query, [table])
            
            # Get column information
            columns_query = """
                SELECT 
                    column_name, 
                    data_type,
                    is_nullable
                FROM information_schema.columns
                WHERE table_name = %s
                ORDER BY ordinal_position
            """
            columns = connector.execute_query(columns_query, [table])
            
            # Get existing indexes
            indexes_query = """
                SELECT
                    i.relname as index_name,
                    array_agg(a.attname) as column_names,
                    ix.indisunique as is_unique,
                    ix.indisprimary as is_primary,
                    am.amname as index_type,
                    pg_get_indexdef(ix.indexrelid) as index_definition
                FROM
                    pg_class t,
                    pg_class i,
                    pg_index ix,
                    pg_attribute a,
                    pg_am am
                WHERE
                    t.oid = ix.indrelid
                    AND i.oid = ix.indexrelid
                    AND a.attrelid = t.oid
                    AND a.attnum = ANY(ix.indkey)
                    AND t.relkind = 'r'
                    AND t.relname = %s
                    AND i.relam = am.oid
                GROUP BY
                    i.relname,
                    ix.indisunique,
                    ix.indisprimary,
                    am.amname,
                    ix.indexrelid
                ORDER BY
                    i.relname
            """
            indexes = connector.execute_query(indexes_query, [table])
            
            db_structure[table] = {
                "statistics": table_stats[0] if table_stats else {},
                "columns": columns,
                "indexes": indexes
            }
        
        # Use PostgreSQL's EXPLAIN to analyze the query
        explain_query = f"EXPLAIN (FORMAT JSON) {query}"
        explain_results = connector.execute_query(explain_query)
        
        if not explain_results or not explain_results[0]:
            return "Failed to generate execution plan for the query."
        
        plan_json = None
        if 'QUERY PLAN' in explain_results[0]:
            plan_json = explain_results[0]['QUERY PLAN'][0]
        else:
            return "Failed to extract query plan from EXPLAIN results."
        
        # Extract potential index candidates using basic parsing
        potential_indexes = extract_potential_indexes(query)
        
        # Check which potential indexes already exist
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
    except Exception as e:
        return f"Error generating index recommendations: {str(e)}"

@mcp.tool()
async def suggest_query_rewrite(query: str, secret_name: str = None, region_name: str = "us-west-2", ctx: Context = None) -> str:
    """
    Suggest optimized rewrites for a SQL query.
    
    Args:
        query: The SQL query to optimize
        secret_name: AWS Secrets Manager secret name containing database credentials (required)
        region_name: AWS region where the secret is stored (default: us-west-2)
    
    Returns:
        Suggestions for query rewrites to improve performance
    """
    context_id = getattr(ctx, 'id', "default") if ctx else "default"
    
    # Check if secret_name is provided
    if not secret_name:
        return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
    
    # Initialize connector with the provided secret name
    connector = PostgresConnector(
        secret_name=secret_name,
        region_name=region_name
    )
    
    if connector.connect():
        db_contexts[context_id] = connector
    else:
        return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
    
    try:
        # Get the execution plan
        explain_query = f"EXPLAIN (FORMAT JSON) {query}"
        explain_results = connector.execute_query(explain_query)
        
        if not explain_results or not explain_results[0]:
            return "Failed to generate execution plan for the query."
        
        plan_json = None
        if 'QUERY PLAN' in explain_results[0]:
            plan_json = explain_results[0]['QUERY PLAN'][0]
        else:
            return "Failed to extract query plan from EXPLAIN results."
        
        # Get schema information for tables in the query
        tables_involved = extract_tables_from_query(query)
        schema_info = get_schema_information(connector, tables_involved)
        
        # Get table statistics
        table_stats = get_table_statistics(connector, tables_involved)
        
        # Get index information
        index_info = get_index_information(connector, tables_involved)
        
        # Analyze the query for common anti-patterns
        anti_patterns = detect_query_anti_patterns(query)
        
        # Analyze query complexity
        complexity = connector.analyze_query_complexity(query)
        
        # Format the response
        response = "## Query Rewrite Suggestions\n\n"
        
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
        
        # Add database context
        response += "### Database Context\n\n"
        for table in tables_involved:
            table_info = next((t for t in table_stats if t.get('table_name') == table), None)
            if table_info:
                response += f"**Table**: `{table}`\n"
                response += f"- **Rows**: {table_info.get('row_count', 'Unknown')}\n"
                response += f"- **Sequential Scans**: {table_info.get('seq_scan', 'Unknown')}\n"
                response += f"- **Index Scans**: {table_info.get('idx_scan', 'Unknown')}\n\n"
        
        # Add schema information
        response += "### Schema Information\n\n"
        for table in tables_involved:
            table_columns = [col for col in schema_info if col.get('table_name') == table]
            if table_columns:
                response += f"**Table**: `{table}`\n"
                for col in table_columns:
                    nullable = "NULL" if col.get('is_nullable') == 'YES' else "NOT NULL"
                    response += f"- `{col.get('column_name')}` ({col.get('data_type')}, {nullable})\n"
                response += "\n"
        
        # Add index information
        response += "### Index Information\n\n"
        for table in tables_involved:
            table_indexes = [idx for idx in index_info if idx.get('table_name') == table]
            if table_indexes:
                response += f"**Table**: `{table}`\n"
                for idx in table_indexes:
                    response += f"- `{idx.get('index_name')}`: {idx.get('index_definition')}\n"
                    response += f"  - Scans: {idx.get('index_scans', 0)}\n"
                response += "\n"
            else:
                response += f"**Table**: `{table}` - No indexes found\n\n"
        
        # Add anti-pattern analysis
        if anti_patterns:
            response += "### Detected Anti-Patterns\n\n"
            for i, issue in enumerate(anti_patterns, 1):
                response += f"#### Issue {i}: {issue['issue']}\n"
                response += f"**Suggestion**: {issue['suggestion']}\n"
                if "example" in issue and issue["example"]:
                    response += f"**Example**: ```sql\n{issue['example']}\n```\n\n"
        else:
            response += "### Detected Anti-Patterns\n\n"
            response += "No obvious anti-patterns detected in the query.\n\n"
        
        # Add execution plan summary
        response += "### Execution Plan Summary\n\n"
        response += f"- **Plan Type**: {plan_json.get('Plan', {}).get('Node Type', 'Unknown')}\n"
        response += f"- **Estimated Cost**: {plan_json.get('Plan', {}).get('Total Cost', 0)}\n"
        response += f"- **Estimated Rows**: {plan_json.get('Plan', {}).get('Plan Rows', 0)}\n\n"
        
        # The model will use the provided data to generate query rewrite suggestions
        response += "## Recommended Query Rewrites\n\n"
        # This section will be filled by the model based on the data provided
        
        return response
    except Exception as e:
        return f"Error generating query rewrite suggestions: {str(e)}"
        
@mcp.tool()
async def show_postgresql_settings(pattern: str = None, secret_name: str = None, region_name: str = "us-west-2", ctx: Context = None) -> str:
    """
    Show PostgreSQL configuration settings with optional filtering.
    
    Args:
        pattern: Optional pattern to filter settings (e.g., "wal" for all WAL-related settings)
        secret_name: AWS Secrets Manager secret name containing database credentials (required)
        region_name: AWS region where the secret is stored (default: us-west-2)
    
    Returns:
        Current PostgreSQL configuration settings in a formatted table
    
    Examples:
        show_postgresql_settings(secret_name="my-db-secret")
        show_postgresql_settings(pattern="wal", secret_name="my-db-secret")
        show_postgresql_settings(pattern="autovacuum", secret_name="my-db-secret")
    """
    context_id = getattr(ctx, 'id', "default") if ctx else "default"
    
    # Check if secret_name is provided
    if not secret_name:
        return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
    
    # Initialize connector with the provided secret name
    connector = PostgresConnector(
        secret_name=secret_name,
        region_name=region_name
    )
    
    if connector.connect():
        db_contexts[context_id] = connector
    else:
        return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
    
    try:
        # Build the query based on whether a pattern is provided
        if pattern:
            query = """
                SELECT name, setting, unit, category, short_desc, context, source
                FROM pg_settings
                WHERE name ILIKE %s
                ORDER BY category, name
            """
            results = connector.execute_query(query, [f"%{pattern}%"])
        else:
            query = """
                SELECT name, setting, unit, category, short_desc, context, source
                FROM pg_settings
                ORDER BY category, name
            """
            results = connector.execute_query(query)
        
        if not results:
            if pattern:
                return f"No settings found matching pattern '{pattern}'."
            else:
                return "No settings found."
        
        # Group settings by category for better organization
        settings_by_category = {}
        for setting in results:
            category = setting['category']
            if category not in settings_by_category:
                settings_by_category[category] = []
            settings_by_category[category].append(setting)
        
        # Format the response
        response = "# PostgreSQL Configuration Settings\n\n"
        
        if pattern:
            response += f"Showing settings matching pattern: '{pattern}'\n\n"
        
        for category, settings in settings_by_category.items():
            response += f"## {category}\n\n"
            response += "| Name | Setting | Unit | Context | Source | Description |\n"
            response += "| ---- | ------- | ---- | ------- | ------ | ----------- |\n"
            
            for setting in settings:
                name = setting['name']
                value = setting['setting']
                unit = setting['unit'] or ''
                context = setting['context']
                source = setting['source']
                desc = setting['short_desc']
                
                response += f"| {name} | {value} | {unit} | {context} | {source} | {desc} |\n"
            
            response += "\n"
        
        response += f"\n{len(results)} setting(s) displayed."
        
        return response
    except Exception as e:
        return f"Error retrieving PostgreSQL settings: {str(e)}"

def validate_read_only_query(query):
    """
    Validate that a query is read-only and safe to execute
    
    Args:
        query (str): The query to validate
        
    Returns:
        tuple: (is_valid, error_message)
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

@mcp.tool()
async def execute_read_only_query(query: str, secret_name: str = None, region_name: str = "us-west-2", 
                                 max_rows: int = 100, ctx: Context = None) -> str:
    """
    Execute a read-only SQL query and return the results.
    
    Args:
        query: The SQL query to execute (must be SELECT, EXPLAIN, or SHOW only)
        secret_name: AWS Secrets Manager secret name containing database credentials (required)
        region_name: AWS region where the secret is stored (default: us-west-2)
        max_rows: Maximum number of rows to return (default: 100)
    
    Returns:
        Query results in a formatted table
    
    Examples:
        execute_read_only_query("SELECT * FROM pg_stat_activity LIMIT 10", secret_name="my-db-secret")
        execute_read_only_query("EXPLAIN ANALYZE SELECT * FROM users WHERE user_id = 123", secret_name="my-db-secret")
        execute_read_only_query("SHOW wal_level", secret_name="my-db-secret")
        execute_read_only_query("SHOW ALL", secret_name="my-db-secret")
    """
    context_id = getattr(ctx, 'id', "default") if ctx else "default"
    
    # Check if secret_name is provided
    if not secret_name:
        return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
    
    # Validate that this is a read-only query
    is_valid, error_message = validate_read_only_query(query)
    if not is_valid:
        return f"Error: {error_message}"
    
    # Initialize connector with the provided secret name
    connector = PostgresConnector(
        secret_name=secret_name,
        region_name=region_name
    )
    
    if connector.connect():
        db_contexts[context_id] = connector
    else:
        return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
    
    try:
        # Set session to read-only mode
        connector.execute_query("SET TRANSACTION READ ONLY")
        connector.execute_query("SET statement_timeout = '30s'")  # 30-second timeout for safety
        
        # Execute the query
        start_time = time.time()
        results = connector.execute_query(query)
        execution_time = time.time() - start_time
        
        if not results:
            return f"Query executed successfully in {execution_time:.2f} seconds, but returned no results."
        
        # Limit the number of rows returned
        if len(results) > max_rows:
            truncated = True
            results = results[:max_rows]
        else:
            truncated = False
        
        # Format the results as a markdown table
        response = f"## Query Results\n\n"
        response += f"Executed in {execution_time:.2f} seconds\n\n"
        
        if truncated:
            response += f"*Results truncated to {max_rows} rows*\n\n"
        
        # Get column names from the first row
        columns = list(results[0].keys())
        
        # Create the header row
        response += "| " + " | ".join(columns) + " |\n"
        response += "| " + " | ".join(["---" for _ in columns]) + " |\n"
        
        # Add data rows
        for row in results:
            # Convert each value to string and handle None values
            row_values = []
            for col in columns:
                val = row.get(col)
                if val is None:
                    row_values.append("NULL")
                else:
                    # Escape pipe characters in the data to prevent breaking the markdown table
                    row_values.append(str(val).replace("|", "\\|"))
            
            response += "| " + " | ".join(row_values) + " |\n"
        
        response += f"\n{len(results)} rows returned" + (" (truncated)" if truncated else "")
        
        return response
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        return f"Error executing query: {str(e)}\n\nDetails:\n{error_details}"
    
@mcp.tool()
async def health_check(ctx: Context = None) -> str:
    """
    Check if the server is running and responsive.
    
    Returns:
        A message indicating the server is healthy
    """
    return "PostgreSQL Performance Analyzer MCP server is running and healthy!"

# Run the server with SSE transport for remote connections
if __name__ == "__main__":
    import argparse
    import logging
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger("postgres-analyzer")
    
    parser = argparse.ArgumentParser(description='PostgreSQL Performance Analyzer MCP Server')
    parser.add_argument('--port', type=int, default=8000, help='Port to run the server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the server to')
    
    args = parser.parse_args()
    
    # Configure the MCP server settings
    mcp.settings.port = args.port
    mcp.settings.host = args.host
    
    print(f"Starting PostgreSQL Performance Analyzer MCP server on {args.host}:{args.port} with SSE transport")
    
    try:
        mcp.run(transport='sse')
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        # If the server crashes, try to restart it
        import time
        time.sleep(5)  # Wait 5 seconds before restarting
        print("Attempting to restart server...")
        mcp.run(transport='sse')