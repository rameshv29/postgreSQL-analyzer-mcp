import logging
import os
from contextlib import asynccontextmanager
from mcp.server.fastmcp import FastMCP

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
        yield
    finally:
        print("Shutting down PostgreSQL Performance Analyzer MCP Server")