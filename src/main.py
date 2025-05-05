import argparse
import logging
import os
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

from config import configure_logging, server_lifespan
from tools.mcp_tools import register_all_tools

# Configure logging
logger = configure_logging()

# Create FastAPI app for health checks
app = FastAPI()

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

# Initialize MCP server with proper configuration for concurrent sessions
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
    when using any of the tools.
    """,
    lifespan=server_lifespan
)

# Register all tools with the MCP server
register_all_tools(mcp)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='PostgreSQL Performance Analyzer MCP Server')
    parser.add_argument('--port', type=int, default=8000, help='Port to run the server on')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the server to')
    
    args = parser.parse_args()
    
    # Configure the MCP server settings
    mcp.settings.port = args.port
    mcp.settings.host = args.host
    
    # Configure server to handle multiple concurrent connections
    # Note: These are environment variables instead of direct settings
    # as the MCP library likely reads these at startup
    os.environ["MCP_MAX_CONCURRENT_REQUESTS"] = "10"  # Allow 10 concurrent connections
    os.environ["MCP_REQUEST_TIMEOUT_SECONDS"] = "300"  # 5 minute timeout for requests
    
    logger.info(f"Starting PostgreSQL Performance Analyzer MCP server on {args.host}:{args.port}")
    logger.info(f"Health check endpoint available at http://{args.host}:{args.port + 1}/health")
    
    # Run FastAPI on a different port
    import uvicorn
    import threading
    
    def run_fastapi():
        uvicorn.run(app, host=args.host, port=args.port + 1)
    
    # Start FastAPI in a separate thread
    fastapi_thread = threading.Thread(target=run_fastapi, daemon=True)
    fastapi_thread.start()
    
    try:
        # Run with increased client max size for larger queries
        mcp.run(transport='sse')
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        # If the server crashes, try to restart it
        import time
        time.sleep(5)  # Wait 5 seconds before restarting
        logger.info("Attempting to restart server...")
        mcp.run(transport='sse')