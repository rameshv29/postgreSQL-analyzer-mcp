import logging
import os
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP
from session_handler import SessionHandler

# Create a global session handler
session_handler = SessionHandler(session_timeout=1800)

def configure_logging():
    """Configure logging for the application"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger("postgres-analyzer")

@asynccontextmanager
async def server_lifespan(server: FastMCP):
    """Manage application lifecycle for the MCP server"""
    try:
        print("Starting PostgreSQL Performance Analyzer MCP Server")
        # Start the session handler
        await session_handler.start()
        yield
    finally:
        # Stop the session handler
        await session_handler.stop()
        print("Shutting down PostgreSQL Performance Analyzer MCP Server")