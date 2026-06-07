import json
import uuid
import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import (
    User, Conversation, Message, MessageResponse, ConversationResponse, MessageCreate, ParticipantResponse
)
from server.auth.jwt_handler import get_current_user

router = APIRouter(prefix="/chat", tags=["chat"])

@router.get("/users")
async def get_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all registered users except the current one."""
    result = await db.execute(select(User).filter(User.id != current_user.id))
    users = result.scalars().all()
    return [{"id": u.id, "username": u.username} for u in users]


@router.get("/conversations", response_model=List[ConversationResponse])
async def get_conversations(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List all conversations that the current user is a participant of."""
    result = await db.execute(select(Conversation))
    all_convs = result.scalars().all()
    
    my_convs = []
    for conv in all_convs:
        try:
            participants = json.loads(conv.participants)
        except Exception:
            continue
            
        if current_user.id in participants:
            # Resolve usernames of all participants
            resolved_participants = []
            for pid in participants:
                u_res = await db.execute(select(User).filter(User.id == pid))
                u = u_res.scalars().first()
                if u:
                    resolved_participants.append(ParticipantResponse(id=u.id, username=u.username))
                    
            # Get the last message in this conversation
            msg_res = await db.execute(
                select(Message)
                .filter(Message.conversation_id == conv.id)
                .order_by(Message.timestamp.desc())
                .limit(1)
            )
            last_msg = msg_res.scalars().first()
            
            my_convs.append(
                ConversationResponse(
                    id=conv.id,
                    participants=resolved_participants,
                    last_message=last_msg.text if last_msg else None,
                    last_message_time=last_msg.timestamp if last_msg else None
                )
            )
            
    # Sort conversations by last message time (or creation time if no messages)
    my_convs.sort(key=lambda x: x.last_message_time or datetime.datetime.min, reverse=True)
    return my_convs


@router.get("/conversations/{conv_id}/messages", response_model=List[MessageResponse])
async def get_messages(
    conv_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all messages from a specific conversation, ordered chronologically."""
    # Check if conversation exists and current user is a participant
    conv_res = await db.execute(select(Conversation).filter(Conversation.id == conv_id))
    conv = conv_res.scalars().first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
        
    try:
        participants = json.loads(conv.participants)
    except Exception:
        raise HTTPException(status_code=500, detail="Malformed conversation data")
        
    if current_user.id not in participants:
        raise HTTPException(status_code=403, detail="Not authorized to view this conversation")
        
    # Get all messages
    msg_res = await db.execute(
        select(Message)
        .filter(Message.conversation_id == conv_id)
        .order_by(Message.timestamp.asc())
    )
    messages = msg_res.scalars().all()
    
    response = []
    for msg in messages:
        # Get sender username
        sender_res = await db.execute(select(User).filter(User.id == msg.sender_id))
        sender = sender_res.scalars().first()
        sender_name = sender.username if sender else "Desconhecido"
        
        response.append(
            MessageResponse(
                id=msg.id,
                sender_id=msg.sender_id,
                sender_name=sender_name,
                text=msg.text,
                timestamp=msg.timestamp,
                is_sent_by_me=(msg.sender_id == current_user.id)
            )
        )
        
    return response


@router.post("/conversations", response_model=ConversationResponse)
async def create_conversation(
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Start a conversation. Payload can contain 'recipient_username' or 'recipient_id'."""
    recipient_id = payload.get("recipient_id")
    recipient_username = payload.get("recipient_username")
    
    recipient = None
    if recipient_id:
        res = await db.execute(select(User).filter(User.id == recipient_id))
        recipient = res.scalars().first()
    elif recipient_username:
        res = await db.execute(select(User).filter(User.username == recipient_username))
        recipient = res.scalars().first()
        
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient user not found")
        
    if recipient.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot start a conversation with yourself")
        
    # Check if a 1-to-1 conversation already exists between these users
    convs_res = await db.execute(select(Conversation))
    all_convs = convs_res.scalars().all()
    
    existing_conv = None
    for conv in all_convs:
        try:
            parts = json.loads(conv.participants)
        except Exception:
            continue
            
        if len(parts) == 2 and current_user.id in parts and recipient.id in parts:
            existing_conv = conv
            break
            
    if existing_conv:
        # Return existing conversation
        return ConversationResponse(
            id=existing_conv.id,
            participants=[
                ParticipantResponse(id=current_user.id, username=current_user.username),
                ParticipantResponse(id=recipient.id, username=recipient.username)
            ]
        )
        
    # Create new conversation
    new_conv = Conversation(
        id=str(uuid.uuid4()),
        participants=json.dumps([current_user.id, recipient.id])
    )
    db.add(new_conv)
    await db.commit()
    await db.refresh(new_conv)
    
    return ConversationResponse(
        id=new_conv.id,
        participants=[
            ParticipantResponse(id=current_user.id, username=current_user.username),
            ParticipantResponse(id=recipient.id, username=recipient.username)
        ]
    )


@router.post("/conversations/{conv_id}/messages", response_model=MessageResponse)
async def send_message(
    conv_id: str,
    msg_data: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Send a message inside a conversation."""
    conv_res = await db.execute(select(Conversation).filter(Conversation.id == conv_id))
    conv = conv_res.scalars().first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
        
    try:
        participants = json.loads(conv.participants)
    except Exception:
        raise HTTPException(status_code=500, detail="Malformed conversation data")
        
    if current_user.id not in participants:
        raise HTTPException(status_code=403, detail="Not authorized to send messages to this conversation")
        
    new_msg = Message(
        id=str(uuid.uuid4()),
        conversation_id=conv_id,
        sender_id=current_user.id,
        text=msg_data.text
    )
    db.add(new_msg)
    await db.commit()
    await db.refresh(new_msg)
    
    # Broadcast through websocket if participants are connected
    # (websocket manager handles this via import or global references)
    from server.chat.websocket import manager
    await manager.broadcast_to_conversation(
        conv_id=conv_id,
        message_data={
            "id": new_msg.id,
            "conversation_id": conv_id,
            "sender_id": current_user.id,
            "sender_name": current_user.username,
            "text": new_msg.text,
            "timestamp": new_msg.timestamp.isoformat(),
            "is_sent_by_me": False  # Recipient will receive it as not sent by them
        },
        exclude_user_id=current_user.id
    )
    
    return MessageResponse(
        id=new_msg.id,
        sender_id=current_user.id,
        sender_name=current_user.username,
        text=new_msg.text,
        timestamp=new_msg.timestamp,
        is_sent_by_me=True
    )
