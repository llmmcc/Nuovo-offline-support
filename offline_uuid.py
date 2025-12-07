import uuid
import hashlib

def generate_offline_uuid(username: str) -> str:
    """
    生成离线模式的Minecraft UUID
    使用Java的UUID.nameUUIDFromBytes算法
    """
    # 离线模式的命名空间UUID
    namespace = uuid.UUID('00000000-0000-0000-0000-000000000000')
    
    # 字符串格式：OfflinePlayer:<username>
    offline_id = f"OfflinePlayer:{username}"
    
    # 生成MD5哈希
    md5_hash = hashlib.md5()
    md5_hash.update(namespace.bytes)
    md5_hash.update(offline_id.encode('utf-8'))
    hash_bytes = md5_hash.digest()
    
    # 转换为UUID对象并设置版本
    offline_uuid = uuid.UUID(bytes=hash_bytes, version=3)
    
    return str(offline_uuid)
