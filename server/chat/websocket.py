import json
import uuid
import datetime
from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.future import select

from server.database import async_session
from server.auth.jwt_handler import verify_access_token
from server.models import Conversation, Message

router = APIRouter(tags=["websocket"])

class ConnectionManager:
    def __init__(self):
        # Key: user_id (string)
        # Value: list of WebSocket connections (supporting multiple devices/tabs per user)
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)

    def disconnect(self, websocket: WebSocket, user_id: str):
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            if not self.active_connections[user_id]:
                self.active_connections.pop(user_id, None)

    async def broadcast_to_conversation(self, conv_id: str, message_data: dict, exclude_user_id: str = None):
        """Send message JSON to all online participants of a conversation."""
        # Find participants
        async with async_session() as db:
            result = await db.execute(select(Conversation).filter(Conversation.id == conv_id))
            conv = result.scalars().first()
            if not conv:
                return
            try:
                participants = json.loads(conv.participants)
            except Exception:
                return

        # Broadcast
        for user_id in participants:
            if exclude_user_id and user_id == exclude_user_id:
                continue
            if user_id in self.active_connections:
                for connection in self.active_connections[user_id]:
                    try:
                        await connection.send_json(message_data)
                    except Exception:
                        # Stale connection, will be cleaned up on disconnect
                        pass

manager = ConnectionManager()

@router.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket, token: str = Query(...)):
    """WebSocket chat endpoint with query-param JWT auth."""
    payload = verify_access_token(token)
    if not payload:
        await websocket.close(code=4001, reason="Invalid token")
        return
        
    user_id = payload.get("sub")
    username = payload.get("username")
    
    await manager.connect(websocket, user_id)
    
    try:
        while True:
            # Keep connection alive and listen for incoming messages (optional if they use REST to send)
            data = await websocket.receive_text()
            try:
                msg_json = json.loads(data)
                conv_id = msg_json.get("conversation_id")
                text = msg_json.get("text")
                
                if not conv_id or not text:
                    continue
                    
                # Save message to DB
                async with async_session() as db:
                    conv_res = await db.execute(select(Conversation).filter(Conversation.id == conv_id))
                    conv = conv_res.scalars().first()
                    if not conv:
                        continue
                        
                    try:
                        participants = json.loads(conv.participants)
                    except Exception:
                        continue
                        
                    if user_id not in participants:
                        continue
                        
                    new_msg = Message(
                        id=str(uuid.uuid4()),
                        conversation_id=conv_id,
                        sender_id=user_id,
                        text=text,
                        timestamp=datetime.datetime.utcnow()
                    )
                    db.add(new_msg)
                    await db.commit()
                    
                    message_data = {
                        "id": new_msg.id,
                        "conversation_id": conv_id,
                        "sender_id": user_id,
                        "sender_name": username,
                        "text": text,
                        "timestamp": new_msg.timestamp.isoformat(),
                        "is_sent_by_me": False
                    }
                    
                # Broadcast message to all other participants
                await manager.broadcast_to_conversation(
                    conv_id=conv_id,
                    message_data=message_data,
                    exclude_user_id=user_id
                )
                
                # Echo back to the sender with 'is_sent_by_me' as True
                sender_data = message_data.copy()
                sender_data["is_sent_by_me"] = True
                await websocket.send_json(sender_data)
                
            except Exception as e:
                print(f"Error handling WebSocket frame: {e}")
                
    except WebSocketDisconnect:
        manager.disconnect(websocket, user_id)
