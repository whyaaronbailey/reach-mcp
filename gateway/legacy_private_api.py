"""Separate private HTTPS listener. Never mount this app on the public OAuth port."""
from legacy_channel import ChannelDenied, MAX_RESULT, encoded, loads


async def respond(send, status, value=None):
    body = b'' if value is None else encoded(value, MAX_RESULT)
    await send({'type':'http.response.start','status':status,'headers':[
        (b'content-type',b'application/json'),(b'cache-control',b'no-store')]})
    await send({'type':'http.response.body','body':body})


class PrivateAPI:
    def __init__(self, channel):
        self.channel = channel

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return
        try:
            path = scope.get('path', '')
            if scope.get('raw_path', b'') != path.encode('ascii') or scope.get('query_string'):
                raise ChannelDenied()
            headers = scope.get('headers', [])
            hosts = [value for key,value in headers if key.lower() == b'host']
            auth = [value for key,value in headers if key.lower() == b'authorization']
            if hosts != [b'192.0.2.1:19444'] or len(auth) != 1:
                raise ChannelDenied()
            lease = self.channel.authenticate(auth[0].decode('ascii'))
            if path == '/channel/next' and scope['method'] == 'GET':
                value = await self.channel.next(lease)
                return await respond(send, 204 if value is None else 200, value)
            if path != '/channel/result' or scope['method'] != 'POST':
                raise ChannelDenied()
            content_types = [value.split(b';')[0].strip() for key,value in headers if key.lower() == b'content-type']
            if content_types != [b'application/json']:
                raise ChannelDenied()
            body = bytearray()
            while True:
                message = await receive()
                if message['type'] == 'http.disconnect':
                    raise ChannelDenied()
                body.extend(message.get('body', b''))
                if len(body) > MAX_RESULT:
                    raise ChannelDenied()
                if not message.get('more_body'):
                    break
            self.channel.submit(lease, loads(bytes(body), MAX_RESULT))
            return await respond(send, 200, {'accepted':True})
        except (ChannelDenied, UnicodeError, ValueError, TypeError):
            return await respond(send, 403, {'error':'Nexus Windows control is unavailable or not permitted.'})
