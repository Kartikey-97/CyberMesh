import sys
sys.path.insert(0, '/app')

from fastapi import FastAPI, HTTPException

app = FastAPI(title="User Service")

USERS = [
    {"id": 1, "name": "Alice", "email": "alice@corp.com", "role": "engineer"},
    {"id": 2, "name": "Bob", "email": "bob@corp.com", "role": "manager"},
    {"id": 3, "name": "Charlie", "email": "charlie@corp.com", "role": "admin"},
    {"id": 4, "name": "Dave", "email": "dave@corp.com", "role": "intern"},
    {"id": 5, "name": "Eve", "email": "eve@corp.com", "role": "engineer"},
]

@app.get("/users")
async def get_users():
    return USERS

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    user = next((u for u in USERS if u["id"] == user_id), None)
    if user:
        return user
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "user-service"}
