"""One shared OAuth gateway and a separate private TLS worker listener."""
import asyncio
import os
from pathlib import Path
from urllib.parse import urlsplit

from channel import Channel, loads
from registry import Registry
from gateway import create_app, load_config, PUBLIC, PREFIX, RESOURCE
from admin import protected_file, protected_bytes, persistent_context
from deployment_policy import deployment_context
from private_api import PrivateAPI


def worker_hosts():
    profile = loads(Path('/run/config/transport.json').read_bytes(), 8192)
    if set(profile) != {'version', 'private_urls'} or profile['version'] != 2:
        raise ValueError('Reviewed transport profile required.')
    urls = profile['private_urls']
    if not isinstance(urls,list) or not 1 <= len(urls) <= 4:
        raise ValueError('One to four explicitly reviewed private authorities required.')
    hosts = []
    for value in urls:
        url = urlsplit(value)
        if (url.scheme != 'https' or not url.hostname or url.port != 19444
                or url.path not in ('', '/') or url.query or url.fragment or url.username or url.password):
            raise ValueError('Dedicated private TLS transport on port 19444 required.')
        hosts.append(url.netloc)
    return hosts



async def main():
    import uvicorn
    os.umask(0o077)
    # Owner guard restoration must attest this exact boot/container before any bind.
    context = deployment_context(protected_file, protected_bytes, fresh=True)
    if context['policy']['public'] != {'origin':PUBLIC,'mcp_path':RESOURCE,'oauth_prefix':PREFIX}:
        raise ValueError('Reviewed public routing policy required.')
    registry = Registry('/state/registry.sqlite3', authorization_context=persistent_context)
    channel = Channel(registry)
    public = uvicorn.Server(uvicorn.Config(create_app(load_config(),channel),
        host='0.0.0.0',port=18885,access_log=False,log_level='critical',
        proxy_headers=False,timeout_keep_alive=10,limit_concurrency=64))
    private = uvicorn.Server(uvicorn.Config(PrivateAPI(channel, allowed_hosts=worker_hosts()),
        host='0.0.0.0',port=19444,ssl_certfile='/run/tls/server.crt',
        ssl_keyfile='/run/tls/server.key',lifespan='off',access_log=False,
        log_level='critical',proxy_headers=False,timeout_keep_alive=10,limit_concurrency=128))
    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(public.serve())
        tasks.create_task(private.serve())


if __name__ == '__main__':
    asyncio.run(main())
