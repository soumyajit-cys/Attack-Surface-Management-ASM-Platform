import os, time, asyncio
os.environ['JWT_SECRET']='test-secret-key-for-ci'
os.environ['SECRETS_ENCRYPTION_KEY']='65oXmy07q8CjkFHoNljDp294eAbZDmRN4bJd1Ax3lo8='
os.environ['REDIS_URL']='redis://localhost:6379/15'
os.environ['DATABASE_URL']='postgresql://sentinel:sentinelpass@localhost:5432/scratch_check'
import app.api.v1.scans as scans_api
scans_api._WS_REVALIDATE_INTERVAL_SECONDS = 0.2
from main import app
from auth import jwt as token_service
from auth.token_store import token_store
from models import User, Organization
from models.scan_history import ScanHistory
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
n=str(time.time_ns())
engine=create_engine('postgresql://sentinel:sentinelpass@localhost:5432/scratch_check')
S=sessionmaker(bind=engine); db=S()
org=Organization(name='wr2-'+n); db.add(org); db.flush()
u=User(organization_id=org.id,username='u'+n,email='e'+n+'@r.com',password_hash='x',role='admin'); db.add(u); db.flush()
s=ScanHistory(organization_id=org.id,target='r.com',status='running',scope='passive'); db.add(s); db.commit(); db.refresh(s)
sid=s.id; uid=u.id
db.close(); engine.dispose()
tok=token_service.create_access_token(uid)

capture = []
async def run():
    scope = {
        "type":"websocket","http_version":"1.1","method":"GET",
        "path":f"/api/v1/scans/{sid}/ws","raw_path":f"/api/v1/scans/{sid}/ws".encode(),
        "query_string":b"",
        "headers":[[b"authorization",b"Bearer "+tok.encode()],[b"origin",b"http://localhost:5173"],[b"host",b"testserver"]],
        "client":("testclient",50000),"server":("testserver",80),"scheme":"ws","state":{},"app":app,"asgi":{"spec_version":"2.0"}}
    state = {"step": 0}
    async def receive2():
        if state["step"] == 0:
            state["step"] = 1
            return {"type":"websocket.connect"}
        await asyncio.sleep(8)
        return {"type":"websocket.disconnect"}
    async def send(message):
        capture.append(message)
    try:
        await asyncio.wait_for(app(scope, receive2, send), timeout=9)
    except asyncio.TimeoutError:
        capture.append({"timeout": True})

asyncio.run(run())
print("TYPES:", [m.get("type") for m in capture])
for m in capture:
    if m.get("type") == "websocket.close":
        print("CLOSE code:", m.get("code"))
