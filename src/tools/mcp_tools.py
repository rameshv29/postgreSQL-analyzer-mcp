"""
MCP tool definitions for PostgreSQL Performance Analyzer.
This file contains all the tool functions that are registered with the MCP server.
"""
import json
import time
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import Context, FastMCP

from db.connector import PostgresConnector
from analysis.structure import (
    get_database_structure, 
    organize_db_structure_by_table,
    analyze_database_structure_for_response
)
from analysis.query import (
    extract_tables_from_query, 
    get_table_statistics, 
    get_schema_information, 
    get_index_information,
    format_query_analysis_response
)
from analysis.patterns import (
    detect_query_patterns, 
    detect_query_anti_patterns, 
    validate_read_only_query
)
from analysis.indexes import (
    extract_potential_indexes,
    get_table_structure_for_index,
    check_existing_indexes,
    format_index_recommendations_response
)

def register_all_tools(mcp: FastMCP):
    """Register all tools with the MCP server"""
    
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
        # Check if secret_name is provided
        if not secret_name:
            return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
        
        # Initialize connector with the provided secret name
        connector = PostgresConnector(
            secret_name=secret_name,
            region_name=region_name
        )
        
        try:
            if not connector.connect():
                return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
            
            # Get comprehensive database structure
            db_structure = get_database_structure(connector)
            
            # Generate the formatted response
            response = analyze_database_structure_for_response(db_structure)
            
            return response
        except Exception as e:
            return f"Error analyzing database structure: {str(e)}"
        finally:
            # Always disconnect when done
            connector.disconnect()
    
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
        # Check if secret_name is provided
        if not secret_name:
            return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
        
        # Initialize connector with the provided secret name
        connector = PostgresConnector(
            secret_name=secret_name,
            region_name=region_name
        )
        
        try:
            if not connector.connect():
                return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
            
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
        finally:
            # Always disconnect when done
            connector.disconnect()
    
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
        # Check if secret_name is provided
        if not secret_name:
            return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
        
        # Initialize connector with the provided secret name
        connector = PostgresConnector(
            secret_name=secret_name,
            region_name=region_name
        )
        
        try:
            if not connector.connect():
                return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
            
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
            response = format_query_analysis_response(
                query=query,
                plan_json=plan_json,
                tables_involved=tables_involved,
                table_stats=table_stats,
                schema_info=schema_info,
                index_info=index_info,
                patterns=patterns,
                anti_patterns=anti_patterns,
                complexity=complexity
            )
            
            return response
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            return f"Error analyzing query: {str(e)}\n\nDetails:\n{error_details}"
        finally:
            # Always disconnect when done
            connector.disconnect()
    
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
        # Check if secret_name is provided
        if not secret_name:
            return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
        
        # Initialize connector with the provided secret name
        connector = PostgresConnector(
            secret_name=secret_name,
            region_name=region_name
        )
        
        try:
            if not connector.connect():
                return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
            
            # First, analyze the database structure to understand the context
            tables_involved = extract_tables_from_query(query)
            if not tables_involved:
                return "Could not identify any tables in the query. Please check the query syntax."
                
            # Get database structure for the tables involved
            db_structure = get_table_structure_for_index(connector, tables_involved)
            
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
            existing_indexes, missing_indexes = check_existing_indexes(potential_indexes, db_structure)
            
            # Format the response
            response = format_index_recommendations_response(
                query=query,
                plan_json=plan_json,
                db_structure=db_structure,
                existing_indexes=existing_indexes,
                missing_indexes=missing_indexes
            )
            
            return response
        except Exception as e:
            return f"Error generating index recommendations: {str(e)}"
        finally:
            # Always disconnect when done
            connector.disconnect()
    
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
        # Check if secret_name is provided
        if not secret_name:
            return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
        
        # Initialize connector with the provided secret name
        connector = PostgresConnector(
            secret_name=secret_name,
            region_name=region_name
        )
        
        try:
            if not connector.connect():
                return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
            
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
        finally:
            # Always disconnect when done
            connector.disconnect()
            
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
        # Check if secret_name is provided
        if not secret_name:
            return "Error: Please provide a valid AWS Secrets Manager secret name containing database credentials."
        
        # Initialize connector with the provided secret name
        connector = PostgresConnector(
            secret_name=secret_name,
            region_name=region_name
        )
        
        try:
            if not connector.connect():
                return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
            
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
        finally:
            # Always disconnect when done
            connector.disconnect()
    
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
        
        try:
            if not connector.connect():
                return f"Failed to connect to database using secret '{secret_name}'. Please check your credentials."
            
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
        finally:
            # Always disconnect when done
            connector.disconnect()
        
    @mcp.tool()
    async def health_check(ctx: Context = None) -> str:
        """
        Check if the server is running and responsive.
        
        Returns:
            A message indicating the server is healthy
        """
        return "PostgreSQL Performance Analyzer MCP server is running and healthy!"