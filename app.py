
import os
import json
import ipaddress
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from dotenv import load_dotenv

# Alibaba Cloud SDK
from alibabacloud_alidns20150109.client import Client as DnsClient
from alibabacloud_alidns20150109 import models as dns_models
from alibabacloud_tea_openapi import models as open_api_models

# load_dotenv()  # 默认加载根目录下的 .env 文件
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env.local")) # 本地调试时使用

ALIYUN_AK = os.getenv("ALIYUN_ACCESS_KEY_ID")
ALIYUN_SK = os.getenv("ALIYUN_ACCESS_KEY_SECRET")
ALIYUN_REGION = os.getenv("ALIYUN_REGION_ID", "cn-hangzhou")
ALIYUN_DOMAIN = os.getenv("ALIYUN_DOMAIN")
ALIYUN_TTL = int(os.getenv("ALIYUN_TTL", "600"))

API_PORT = int(os.getenv("API_PORT", "3000"))
API_TOKEN = os.getenv("API_TOKEN")

DDNS_RECORDS_ENV = os.getenv("DDNS_RECORDS")

if not (ALIYUN_AK and ALIYUN_SK and ALIYUN_DOMAIN and DDNS_RECORDS_ENV and API_TOKEN):
    raise RuntimeError("Missing required envs: ALIYUN_ACCESS_KEY_ID / ALIYUN_ACCESS_KEY_SECRET / ALIYUN_DOMAIN / DDNS_RECORDS / API_TOKEN")

try:
    DDNS_RECORDS: List[Dict[str, str]] = json.loads(DDNS_RECORDS_ENV)
    assert isinstance(DDNS_RECORDS, list)
except Exception as e:
    raise RuntimeError(f"Invalid DDNS_RECORDS JSON: {e}")

def create_client() -> DnsClient:
    """
    创建阿里云 DNS 客户端, endpoint 固定为华东 1 区
    """
    cfg = open_api_models.Config(
        access_key_id=ALIYUN_AK,
        access_key_secret=ALIYUN_SK,
        region_id=ALIYUN_REGION,
        endpoint="alidns.cn-hangzhou.aliyuncs.com",
    )
    return DnsClient(cfg)

def ipv6_pd_prefix(ipv6: str) -> str:
    """
    提取 IPv6 前 4 段 (PD 前缀)
    """
    addr = ipaddress.IPv6Address(ipv6)
    # exploded 是 8 段零扩展
    parts = addr.exploded.split(":")
    return ":".join(parts[:4])

def ipv6_last64(ipv6: str) -> str:
    """
    提取 IPv6 的后 4 段 (后 64 位)
    """
    addr = ipaddress.IPv6Address(ipv6)
    parts = addr.exploded.split(":")
    return ":".join(parts[4:8])

def make_global_from_pd_and_ll(pd_prefix: str, link_local: str) -> str:
    """
    用新的 PD 与 link-local 的后 64 位拼出全局地址
    """
    suffix = ipv6_last64(link_local)
    return f"{pd_prefix}:{suffix}"

async def find_aaaa_record(client: DnsClient, rr: str) -> Optional[dns_models.DescribeDomainRecordsResponseBodyDomainRecordsRecord]:
    """
    查找精确 RR 的 AAAA 记录 (若存在返回第一条)
    """
    req = dns_models.DescribeDomainRecordsRequest(
        domain_name=ALIYUN_DOMAIN,
        rrkey_word=rr,
        type="AAAA",
        page_number=1,
        page_size=100,
    )
    resp = client.describe_domain_records(req)
    records = (resp.body.domain_records.record or []) if resp and resp.body and resp.body.domain_records else []
    for rec in records:
        # 精确匹配 RR + AAAA
        if rec.rr == rr and rec.type == "AAAA":
            return rec
    return None

async def upsert_aaaa_record(client: DnsClient, rr: str, value: str, ttl: int) -> Dict[str, Any]:
    """
    更新或新增 AAAA 记录
    """
    existing = await find_aaaa_record(client, rr)
    if existing:
        same_value = (existing.value == value)
        same_ttl = (int(existing.ttl) == ttl if existing.ttl is not None else False)
        if same_value and same_ttl:
            return {"action": "noop", "recordId": existing.record_id, "rr": rr, "value": value}

        up_req = dns_models.UpdateDomainRecordRequest(
            record_id=existing.record_id,
            rr=rr,
            type="AAAA",
            value=value,
            ttl=ttl,
        )
        up_resp = client.update_domain_record(up_req)
        return {"action": "update", "recordId": (up_resp.body.record_id if up_resp and up_resp.body else None), "rr": rr, "value": value}
    else:
        add_req = dns_models.AddDomainRecordRequest(
            domain_name=ALIYUN_DOMAIN,
            rr=rr,
            type="AAAA",
            value=value,
            ttl=ttl,
        )
        add_resp = client.add_domain_record(add_req)
        return {"action": "add", "recordId": (add_resp.body.record_id if add_resp and add_resp.body else None), "rr": rr, "value": value}

# ---------- FastAPI ----------

class DdnsBody(BaseModel):
    ipv6: str  # 监控节点上传的新 IPv6 (全局地址)

app = FastAPI(title="DDNS API (FastAPI)")

@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/api")
async def ddns_update(request: Request, body: DdnsBody):
    # 校验访问令牌
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer ") or auth[7:] != API_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing token")
    # 校验 IPv6
    try:
        addr = ipaddress.IPv6Address(body.ipv6)
        if addr.is_link_local:
            raise ValueError("Input IPv6 must be a global unicast address")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid IPv6: {e}")

    pd = ipv6_pd_prefix(body.ipv6)
    client = create_client()

    results = []
    for item in DDNS_RECORDS:
        rr = item.get("rr")
        ll = item.get("ll")
        if not rr or not ll:
            results.append({"rr": rr, "error": "invalid record item"})
            continue
        try:
            # 解析 link-local, 确保合法
            _ = ipaddress.IPv6Address(ll)  # 若非法则会抛出异常
            target = make_global_from_pd_and_ll(pd, ll)
            r = await upsert_aaaa_record(client, rr, target, ALIYUN_TTL)
            results.append({"rr": rr, "target": target, **r})
        except Exception as e:
            results.append({"rr": rr, "error": str(e)})

    return {"ok": True, "pdPrefix": pd, "domain": ALIYUN_DOMAIN, "updated": results}

# 便于 Uvicorn 直接启动: python app.py
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=API_PORT, reload=False)
