# PostgreSQL Analyzer MCP

A Model Context Protocol (MCP) server for PostgreSQL database performance analysis and optimization.

## Overview

PostgreSQL Analyzer MCP is a powerful tool that leverages AI to help database administrators and developers optimize their PostgreSQL databases. It provides comprehensive analysis of database structure, query performance, index usage, and configuration settings, along with actionable recommendations for improvement.

This tool runs as a remote MCP server using Server-Sent Events (SSE) transport, allowing it to be deployed centrally and accessed by any MCP-compatible client, including Amazon Q Developer CLI, Claude and other AI assistants that support the MCP protocol.

## ⚠️ Disclaimer

**EXPERIMENTAL**: This project is experimental and provided as a demonstration of what's possible with MCP and PostgreSQL. All recommendations and code should be carefully reviewed before implementation in any production environment.

**NOT OFFICIAL**: This is a personal project and not affiliated with, endorsed by, or representative of any organization I work for or contribute to. All opinions and approaches are my own.

**NO LIABILITY**: This tool is provided "as is" without warranty of any kind. Use at your own risk. The author is not liable for any damages or issues arising from the use of this software.

## Features

- **Database Structure Analysis**: Analyze tables, columns, indexes, and foreign keys
- **Query Performance Analysis**: Analyze execution plans and identify bottlenecks
- **Index Recommendations**: Get suggestions for new indexes based on query patterns
- **Query Optimization**: Receive suggestions for query rewrites to improve performance
- **Slow Query Identification**: Find and analyze slow-running queries
- **Database Health Dashboard**: Get a comprehensive overview of database health metrics
- **Index Usage Analysis**: Identify unused, duplicate, or bloated indexes
- **Read-Only Query Execution**: Safely execute read-only queries for verification

## Security

This tool operates in **read-only mode** by default. All database connections are established with `SET TRANSACTION READ ONLY` to prevent any accidental modifications to your database. The query execution functionality is strictly limited to SELECT, EXPLAIN, and SHOW commands.

## Installation

### Prerequisites

- Python 3.12+ (or Docker)
- Amazon Aurora or RDS PostgreSQL database
- AWS account (for Secrets Manager, optional)

### Setup

#### Option 1: Local Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/postgres-performance-mcp.git
   cd postgres-performance-mcp
   ```

2. Create virtual environment and Install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate 
   pip install -r requirements.txt
   ```

#### Option 2: Docker Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/postgres-performance-mcp.git
   cd postgres-performance-mcp
   ```

2. Build the Docker image:
   ```bash
   docker build -t postgres-analyzer-mcp -f Dockerfile .
   ```

3. Run the Docker container:
   ```bash
   docker run -p 8000:8000 postgres-analyzer-mcp
   ```

   For AWS credentials (if using Secrets Manager):
   ```bash
   docker run -p 8000:8000 \
     -e AWS_ACCESS_KEY_ID=your_access_key \
     -e AWS_SECRET_ACCESS_KEY=your_secret_key \
     -e AWS_DEFAULT_REGION=your_region \
     postgres-analyzer-mcp
   ```

3. Configure your database credentials:
   - Option 1: Store credentials in AWS Secrets Manager (recommended)
   - Option 2: Provide credentials directly when using the tools

## Usage

### Starting the Server

#### Local:
```bash
python src/main.py --host 0.0.0.0 --port 8000
```

#### Docker:
```bash
# The server starts automatically when running the container
docker run -p 8000:8000 postgres-analyzer-mcp
```

### Configuring MCP Clients

To connect to your remote MCP server, configure your MCP client with:

```
Server URL: http://your-server-address:8000/
Transport: SSE (Server-Sent Events)
```

### Using with an MCP Client

Connect to the server using any MCP-compatible client and use the available tools:

```
analyze_database_structure(secret_name="my-postgres-db-credentials", region_name="us-west-2")
```

### Available Tools

- `analyze_database_structure`: Analyze database schema and provide optimization recommendations
- `get_slow_queries`: Identify slow-running queries in the database
- `analyze_query`: Analyze a SQL query and provide optimization recommendations
- `recommend_indexes`: Recommend indexes for a given SQL query
- `suggest_query_rewrite`: Suggest optimized rewrites for a SQL query
- `database_health_dashboard`: Generate a comprehensive health dashboard for the database
- `query_optimization_wizard`: Interactive wizard to optimize a SQL query step by step
- `analyze_index_usage`: Analyze index usage patterns and identify unused or inefficient indexes
- `execute_read_only_query`: Execute a read-only SQL query and return the results
- `show_postgresql_settings`: Show PostgreSQL configuration settings with optional filtering
- `health_check`: Check if the server is running and responsive

## Customization

The real power of this tool comes from customizing it to your specific environment:

- Add custom analysis rules tailored to your database usage patterns
- Integrate with your monitoring systems
- Customize recommendations based on your organization's best practices
- Add domain-specific knowledge about your data model
- Extend with additional tools specific to your needs

## AWS Secrets Manager Setup

To use AWS Secrets Manager for storing database credentials:

1. Create a secret in AWS Secrets Manager with the following keys:
   - `host`: Database hostname
   - `port`: Database port (usually 5432)
   - `dbname`: Database name
   - `username`: Database username
   - `password`: Database password

2. Ensure your AWS credentials are configured with appropriate permissions to access the secret.

3. Use the secret name when calling the tools:
   ```
   analyze_query(query="SELECT * FROM users WHERE user_id = 123", secret_name="my-postgres-db-credentials")
   ```

## PostgreSQL Configuration

For optimal performance analysis, we recommend enabling the following extensions:

```sql
CREATE EXTENSION pg_stat_statements;
CREATE EXTENSION pg_buffercache;
```

And adding these settings to your `postgresql.conf`:

```
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.track = all
```

## Examples

### Analyzing Database Structure

```
analyze_database_structure(secret_name="my-postgres-db-credentials")
```

### Analyzing a Query

```
analyze_query(
    query="SELECT * FROM orders JOIN customers ON orders.customer_id = customers.id WHERE orders.status = 'pending'",
    secret_name="my-postgres-db-credentials"
)
```

### Getting Index Recommendations

```
recommend_indexes(
    query="SELECT * FROM products WHERE category = 'electronics' AND price < 100",
    secret_name="my-postgres-db-credentials"
)
```

### Executing a Read-Only Query

```
execute_read_only_query(
    query="SELECT schemaname, relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10",
    secret_name="my-postgres-db-credentials"
)
```

## Deploying to a Remote Server

To deploy the MCP server to a remote machine:

1. Install Docker on your remote server
2. Copy the project files to the server or clone from your repository
3. Build and run the Docker container:
   ```bash
   docker build -t postgres-analyzer-mcp -f Dockerfile .
   docker run -d -p 8000:8000 postgres-analyzer-mcp
   ```
4. Consider using a process manager like `docker-compose` or `systemd` to ensure the container restarts if the server reboots

For secure access, consider setting up:
- A reverse proxy with SSL/TLS (like Nginx or Traefik)
- Authentication middleware
- Firewall rules to restrict access

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- PostgreSQL community for their documentation
- MCP protocol developers for enabling AI-powered tools
- This project was created using vibe coding - an AI-assisted development approach that combines human expertise with AI capabilities to create robust, maintainable software solutions.
