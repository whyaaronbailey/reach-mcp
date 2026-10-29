"""Separate private HTTPS listener. Never mount this app on the public OAuth port."""
from channel import ChannelDenied, MAX_RESULT, encoded, loads


async def respond(send, status, value=None):
    body = b'' if value is None else encoded(value, MAX_RESULT)
    await send({'type':'http.response.start','status':status,'headers':[
        (b'content-type',b'application/json'),(b'cache-control',b'no-store')]})
    await send({'type':'http.response.body','body':body})


class PrivateAPI:
    """Private TLS worker protocol. Never proxy these paths through OAuth/Funnel."""
    def __init__(self, channel, allowed_hosts):
        if not isinstance(allowed_hosts,(tuple,list)) or not allowed_hosts:
            raise ValueError('An explicit private listener authority allowlist is required.')
        self.channel = channel
        self.allowed_hosts = frozenset(value.encode('ascii') for value in allowed_hosts)
        if any(not value or b'/' in value or b'@' in value for value in self.allowed_hosts):
            raise ValueError('Invalid private authority.')

    async def __call__(self, scope, receive, send):
        import asyncio
        if scope['type'] != 'http':
            return
        try:
            path = scope.get('path','')
            handlers = {
                '/worker/enroll':self.channel.worker_enroll,
                '/worker/connect':self.channel.worker_connect,
                '/worker/next':self.channel.worker_next,
                '/worker/heartbeat':self.channel.worker_heartbeat,
                '/worker/result':self.channel.worker_result,
                '/worker/revoke':self.channel.worker_revoke,
            }
            if (scope.get('raw_path',b'') != path.encode('ascii') or scope.get('query_string')
                    or scope.get('method') != 'POST' or path not in handlers):
                raise ChannelDenied()
            headers = scope.get('headers',[])
            hosts = [value for key,value in headers if key.lower()==b'host']
            auth = [value for key,value in headers if key.lower()==b'authorization']
            types = [value.split(b';')[0].strip() for key,value in headers if key.lower()==b'content-type']
            if len(hosts)!=1 or hosts[0] not in self.allowed_hosts or len(auth)!=1 or types!=[b'application/json']:
                raise ChannelDenied()
            from registry import token_digest
            authorization = auth[0].decode('ascii')
            token_digest(authorization)  # Strict syntax before reading a potentially large body.
            maximum = MAX_RESULT if path=='/worker/result' else 4096
            lengths = [value for key,value in headers if key.lower()==b'content-length']
            if len(lengths)>1 or (lengths and (not lengths[0].isdigit() or int(lengths[0])>maximum)):
                raise ChannelDenied()
            body = bytearray()
            async with asyncio.timeout(10):
                while True:
                    message = await receive()
                    if message['type'] != 'http.request':
                        raise ChannelDenied()
                    body.extend(message.get('body',b''))
                    if len(body)>maximum:
                        raise ChannelDenied()
                    if not message.get('more_body'):
                        break
            payload = loads(bytes(body),maximum)
            if path=='/worker/next':
                result = await handlers[path](authorization,payload)
            else:
                result = handlers[path](authorization,payload)
            return await respond(send,204 if result is None else 200,result)
        except (ChannelDenied, UnicodeError, ValueError, TypeError, KeyError, asyncio.TimeoutError):
            return await respond(send,403,{'error':str(ChannelDenied())})
