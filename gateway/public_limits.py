"""Bound every public request before OAuth parsing, including DCR and token forms."""
import asyncio
import re

from channel import MAX_REQUEST


class PublicBodyLimit:
    def __init__(self, app, maximum=MAX_REQUEST, seconds=10):
        self.app,self.maximum,self.seconds=app,maximum,seconds

    async def __call__(self, scope, receive, send):
        if scope['type']!='http':
            return await self.app(scope,receive,send)
        async def reject(status):
            await send({'type':'http.response.start','status':status,'headers':[
                (b'content-type',b'application/json'),(b'cache-control',b'no-store')]})
            await send({'type':'http.response.body','body':b'{"error":"Request body unavailable or too large."}'})
        lengths=[value for key,value in scope.get('headers',[]) if key.lower()==b'content-length']
        if lengths and (len(lengths)!=1 or not re.fullmatch(b'[0-9]{1,9}',lengths[0])):
            return await reject(400)
        if lengths and int(lengths[0])>self.maximum:
            return await reject(413)
        body=bytearray()
        try:
            async with asyncio.timeout(self.seconds):
                while True:
                    message=await receive()
                    if message['type']=='http.disconnect':
                        return
                    body.extend(message.get('body',b''))
                    if len(body)>self.maximum:
                        return await reject(413)
                    if not message.get('more_body'):
                        break
        except TimeoutError:
            return await reject(408)
        sent=False
        async def replay():
            nonlocal sent
            if sent:
                return await receive()
            sent=True
            return {'type':'http.request','body':bytes(body),'more_body':False}
        return await self.app(scope,replay,send)
