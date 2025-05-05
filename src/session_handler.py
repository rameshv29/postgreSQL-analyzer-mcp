import asyncio
import logging
import time
from typing import Dict, Any
from contextlib import asynccontextmanager

logger = logging.getLogger("postgres-analyzer")

class SessionHandler:
    def __init__(self, session_timeout=1800):
        self.sessions = {}
        self.session_locks = {}
        self.session_timeout = session_timeout  # in seconds
        self.cleanup_task = None
    
    async def start(self):
        """Start the session handler and its cleanup task"""
        self.cleanup_task = asyncio.create_task(self._cleanup_expired_sessions())
        logger.info("Session handler started")
    
    async def stop(self):
        """Stop the session handler and its cleanup task"""
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Session handler stopped")
    
    def get_session_lock(self, session_id: str):
        """Get or create a lock for the given session"""
        if session_id not in self.session_locks:
            self.session_locks[session_id] = asyncio.Lock()
            self.sessions[session_id] = {
                "created_at": time.time(),
                "last_access": time.time()
            }
            logger.info(f"New session registered: {session_id}")
        else:
            # Update last access time
            self.sessions[session_id]["last_access"] = time.time()
            
        return self.session_locks[session_id]
    
    async def _cleanup_expired_sessions(self):
        """Periodically clean up expired sessions"""
        try:
            while True:
                await asyncio.sleep(60)  # Check every minute
                current_time = time.time()
                expired_sessions = [
                    sid for sid, session in self.sessions.items()
                    if current_time - session["last_access"] > self.session_timeout
                ]
                
                for sid in expired_sessions:
                    if sid in self.sessions:
                        del self.sessions[sid]
                    if sid in self.session_locks:
                        del self.session_locks[sid]
                    logger.info(f"Expired session removed: {sid}")
                
                if expired_sessions:
                    logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
                
                # Log active session count
                logger.info(f"Active sessions: {len(self.sessions)}")
        except asyncio.CancelledError:
            logger.info("Session cleanup task cancelled")
        except Exception as e:
            logger.error(f"Error in session cleanup: {str(e)}")
