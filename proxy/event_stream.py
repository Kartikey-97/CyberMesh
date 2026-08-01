import asyncio
from typing import Set
from shared.event_schema import CyberMeshEvent

class EventBroadcaster:
    def __init__(self):
        self.subscribers: Set[asyncio.Queue] = set()
        
    def subscribe(self) -> asyncio.Queue:
        q = asyncio.Queue()
        self.subscribers.add(q)
        return q
        
    def unsubscribe(self, q: asyncio.Queue):
        if q in self.subscribers:
            self.subscribers.remove(q)
            
    def broadcast(self, event: CyberMeshEvent):
        event_json = event.to_json()
        for q in self.subscribers:
            try:
                q.put_nowait(event_json)
            except asyncio.QueueFull:
                pass

broadcaster = EventBroadcaster()
