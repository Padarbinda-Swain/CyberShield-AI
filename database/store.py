"""Storage layer. MongoDB Atlas (motor) in production; JSON-file fallback so the app runs with zero setup."""
from __future__ import annotations
import asyncio, json, os, pathlib, uuid
from collections import Counter
from datetime import datetime, timedelta, timezone


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def summarize(scans: list[dict]) -> dict:
    v = Counter(s["verdict"] for s in scans)
    return {"total": len(scans), "safe": v["SAFE"], "suspicious": v["SUSPICIOUS"], "dangerous": v["HIGH_RISK"],
            "by_type": dict(Counter(s["input_type"] for s in scans)),
            "threats": dict(Counter(s["threat_type"] for s in scans if s["verdict"] != "SAFE"))}


def trend(scans: list[dict], days: int = 14) -> list[dict]:
    base = datetime.now(timezone.utc).date()
    keys = [(base - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    c = {k: {"date": k, "safe": 0, "suspicious": 0, "dangerous": 0} for k in keys}
    for s in scans:
        d = s["created_at"][:10]
        if d in c: c[d][{"SAFE": "safe", "SUSPICIOUS": "suspicious", "HIGH_RISK": "dangerous"}[s["verdict"]]] += 1
    return list(c.values())


class FileStore:
    kind = "file"

    def __init__(self, path: str):
        self.path = pathlib.Path(path); self.lock = asyncio.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.d = json.loads(self.path.read_text()) if self.path.exists() else {"users": [], "scans": []}

    def _save(self): self.path.write_text(json.dumps(self.d))

    async def create_user(self, u):
        async with self.lock:
            u = {**u, "id": uuid.uuid4().hex, "created_at": now()}; self.d["users"].append(u); self._save(); return u

    async def get_user_by_email(self, email): return next((u for u in self.d["users"] if u["email"] == email), None)
    async def get_user(self, uid): return next((u for u in self.d["users"] if u["id"] == uid), None)
    async def count_users(self): return len(self.d["users"])

    async def insert_scan(self, s):
        async with self.lock:
            s = {**s, "id": uuid.uuid4().hex, "created_at": now()}; self.d["scans"].append(s); self._save(); return s

    async def list_scans(self, uid, limit=50, skip=0, verdict=None, input_type=None):
        r = [s for s in reversed(self.d["scans"]) if s["user_id"] == uid and (not verdict or s["verdict"] == verdict) and (not input_type or s["input_type"] == input_type)]
        return r[skip: skip + limit], len(r)

    async def get_scan(self, sid, uid): return next((s for s in self.d["scans"] if s["id"] == sid and s["user_id"] == uid), None)

    async def delete_scan(self, sid, uid):
        async with self.lock:
            n = len(self.d["scans"]); self.d["scans"] = [s for s in self.d["scans"] if not (s["id"] == sid and s["user_id"] == uid)]
            self._save(); return len(self.d["scans"]) < n

    async def user_stats(self, uid):
        mine = [s for s in self.d["scans"] if s["user_id"] == uid]
        return {**summarize(mine), "trend": trend(mine), "avg_risk": round(sum(s["risk_score"] for s in mine) / len(mine)) if mine else 0}

    async def admin_stats(self):
        allscans = self.d["scans"]; bad = [s for s in allscans if s["verdict"] == "HIGH_RISK"]
        recent = [{"input": s["input"][:80] if s["input_type"] in ("url", "website") else "[message content hidden]", "input_type": s["input_type"],
                   "threat_type": s["threat_type"], "risk_score": s["risk_score"], "created_at": s["created_at"]} for s in reversed(bad[-10:])]
        return {**summarize(allscans), "users": len(self.d["users"]), "trend": trend(allscans, 14), "recent_malicious": recent}


class MongoStore:
    kind = "mongodb"

    def __init__(self, uri: str, dbname: str):
        from motor.motor_asyncio import AsyncIOMotorClient
        self.db = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)[dbname]

    async def init(self):
        await self.db.users.create_index("email", unique=True)
        await self.db.scans.create_index([("user_id", 1), ("created_at", -1)])
        await self.db.scans.create_index("verdict")

    @staticmethod
    def _out(d):
        if d and "_id" in d: d["id"] = str(d.pop("_id"))
        return d

    async def create_user(self, u):
        u = {**u, "created_at": now()}; r = await self.db.users.insert_one(u); u["id"] = str(r.inserted_id); u.pop("_id", None); return u

    async def get_user_by_email(self, email): return self._out(await self.db.users.find_one({"email": email}))

    async def get_user(self, uid):
        from bson import ObjectId
        try: return self._out(await self.db.users.find_one({"_id": ObjectId(uid)}))
        except Exception: return None

    async def count_users(self): return await self.db.users.count_documents({})

    async def insert_scan(self, s):
        s = {**s, "created_at": now()}; r = await self.db.scans.insert_one(s); s["id"] = str(r.inserted_id); s.pop("_id", None); return s

    async def list_scans(self, uid, limit=50, skip=0, verdict=None, input_type=None):
        q = {"user_id": uid, **({"verdict": verdict} if verdict else {}), **({"input_type": input_type} if input_type else {})}
        cur = self.db.scans.find(q).sort("created_at", -1).skip(skip).limit(limit)
        return [self._out(d) async for d in cur], await self.db.scans.count_documents(q)

    async def get_scan(self, sid, uid):
        from bson import ObjectId
        try: return self._out(await self.db.scans.find_one({"_id": ObjectId(sid), "user_id": uid}))
        except Exception: return None

    async def delete_scan(self, sid, uid):
        from bson import ObjectId
        try: return (await self.db.scans.delete_one({"_id": ObjectId(sid), "user_id": uid})).deleted_count > 0
        except Exception: return False

    async def _agg(self, match):
        proj = {"verdict": 1, "input_type": 1, "threat_type": 1, "created_at": 1, "risk_score": 1}
        docs = [d async for d in self.db.scans.find(match, proj).sort("created_at", -1).limit(20000)]
        return docs

    async def user_stats(self, uid):
        d = await self._agg({"user_id": uid})
        return {**summarize(d), "trend": trend(d), "avg_risk": round(sum(s["risk_score"] for s in d) / len(d)) if d else 0}

    async def admin_stats(self):
        d = await self._agg({})
        since = (datetime.now(timezone.utc) - timedelta(days=14)).isoformat()
        cur = self.db.scans.find({"verdict": "HIGH_RISK"}, {"input": 1, "input_type": 1, "threat_type": 1, "risk_score": 1, "created_at": 1}).sort("created_at", -1).limit(10)
        recent = [{"input": s["input"][:80] if s["input_type"] in ("url", "website") else "[message content hidden]", "input_type": s["input_type"],
                   "threat_type": s["threat_type"], "risk_score": s["risk_score"], "created_at": s["created_at"]} async for s in cur]
        return {**summarize(d), "users": await self.count_users(), "trend": trend(d, 14), "recent_malicious": recent}


async def create_store():
    uri = os.getenv("MONGODB_URI")
    if uri:
        s = MongoStore(uri, os.getenv("MONGODB_DB", "cybershield")); await s.init(); return s
    return FileStore(os.getenv("LOCAL_DB_PATH", "data/local_db.json"))
