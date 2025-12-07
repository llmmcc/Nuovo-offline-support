from fastapi import FastAPI, Request
from database import engine, Base
from api import router
import os
import requests
from zipfile import ZipFile
from io import BytesIO
import json
import shutil
import hashlib

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")
with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

ASSETS_URL = CONFIG.get(
    "assetsUrl", "https://github.com/FiguraMC/Assets/archive/refs/heads/main.zip")
ASSETS_DIR = CONFIG.get("assetsDir", "assets")


def calculate_file_hash(file_path):
    hash_func = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    return hash_func.hexdigest()


def generate_file_index(directory):
    file_index = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            relative_path = os.path.relpath(
                file_path, directory).replace("\\", "/")
            file_index[relative_path] = calculate_file_hash(file_path)
    return file_index


def fetch_and_extract_assets():
    response = requests.get(ASSETS_URL)
    response.raise_for_status()
    with ZipFile(BytesIO(response.content)) as zip_file:
        zip_file.extractall(ASSETS_DIR)

    assets_main_dir = os.path.join(ASSETS_DIR, "Assets-main")
    file_index = generate_file_index(assets_main_dir + "/v2")

    v2_json_path = os.path.join(assets_main_dir, "v2.json")
    with open(v2_json_path, "w", encoding="utf-8") as f:
        json.dump(file_index, f, indent=4)


if not os.path.exists(ASSETS_DIR):
    os.makedirs(ASSETS_DIR, exist_ok=True)
    fetch_and_extract_assets()
else:
    shutil.rmtree(ASSETS_DIR)
    os.makedirs(ASSETS_DIR, exist_ok=True)
    fetch_and_extract_assets()

# 在 main.py 的 FastAPI 应用创建后添加中间件

app = FastAPI()

# 添加中间件拦截所有Mojang API请求
@app.middleware("http")
async def intercept_mojang_requests(request: Request, call_next):
    # 检查是否是Mojang验证请求
    path = str(request.url.path)
    
    # 如果请求的路径包含Mojang相关路径，拦截并返回模拟响应
    if "sessionserver.mojang.com" in str(request.url) or "session/minecraft/hasJoined" in path:
        # 从查询参数获取用户名
        username = request.query_params.get("username", "")
        if not username:
            # 尝试从查询字符串解析
            query_str = str(request.url.query)
            for param in query_str.split("&"):
                if param.startswith("username="):
                    username = param.split("=")[1]
                    break
        
        if not username:
            return Response(content="Missing username", status_code=400)
        
        # 生成离线UUID
        from offline_uuid import generate_offline_uuid
        user_uuid = generate_offline_uuid(username)
        
        # 构建模拟的Mojang响应
        import json
        mock_response = {
            "id": user_uuid.replace("-", ""),
            "name": username,
            "properties": []
        }
        
        return Response(
            content=json.dumps(mock_response),
            media_type="application/json",
            status_code=200
        )
    
    # 正常处理其他请求
    response = await call_next(request)
    return response

# 现有的collapse_double_slashes中间件
@app.middleware("http")
async def collapse_double_slashes(request: Request, call_next):
    path = request.url.path
    normalized_path = "/" + "/".join(filter(None, path.split("/")))
    if normalized_path != path:
        request.scope["path"] = normalized_path
    return await call_next(request)

app.include_router(router)

Base.metadata.create_all(bind=engine)


@app.middleware("http")
async def collapse_double_slashes(request: Request, call_next):
    path = request.url.path
    normalized_path = "/" + "/".join(filter(None, path.split("/")))
    if normalized_path != path:
        request.scope["path"] = normalized_path
    return await call_next(request)

app.include_router(router)

Base.metadata.create_all(bind=engine)
