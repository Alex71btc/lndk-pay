#!/usr/bin/env python3
"""Extract only LND connection settings from an existing app container.

Never copy its data volume, UI password, Nostr keys, or Phoenixd credentials.
No secret file contents are read or printed.
"""
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from urllib.parse import urlsplit


def credential_source(container, target):
    target = PurePosixPath(target)
    if not target.is_absolute() or '..' in target.parts:
        raise ValueError('LND credential path must be absolute')
    mounts = sorted(container.get('Mounts', []), key=lambda m: len(m.get('Destination', '')), reverse=True)
    for mount in mounts:
        destination = PurePosixPath(mount['Destination'])
        if target == destination or destination in target.parents:
            if mount.get('Type') != 'bind':
                raise ValueError('LND credentials must be in a host bind mount for this test helper')
            source = Path(mount['Source']) / str(target.relative_to(destination))
            if source.is_file():
                return str(source)
            # Docker Desktop reports Linux bind sources as VM paths. Only
            # remove the exact shared-host prefix, and verify the host file.
            # Native Docker paths always take precedence; never guess secrets
            # from another checkout when the reported file does not exist.
            desktop_prefix = PurePosixPath('/host_mnt')
            if desktop_prefix in source.parents:
                host_source = Path('/') / source.relative_to(desktop_prefix)
                if host_source.is_file():
                    return str(host_source)
            raise ValueError('LND credential file is not available on the host: ' + str(source))
    raise ValueError('No host bind mount found for LND credential path: ' + str(target))


def configuration(container):
    env = dict(value.split('=', 1) for value in container.get('Config', {}).get('Env', []) if '=' in value)
    url = env.get('LND_REST_URL', '').strip().rstrip('/')
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Existing container has no usable LND_REST_URL')
    if parsed.hostname in {'localhost', '127.0.0.1', '::1'}:
        raise ValueError('Existing LND URL uses container loopback; configure a LAN-reachable LND REST URL first')
    insecure = env.get('LND_REST_INSECURE', 'false')
    mounts = []
    for key, default, target in [
        ('LND_TLS_CERT_PATH', '/secrets/tls.cert', '/test-lnd/tls.cert'),
        ('LND_MACAROON_PATH', '/secrets/admin.macaroon', '/test-lnd/admin.macaroon'),
    ]:
        source = credential_source(container, env.get(key) or default)
        mounts.append({'type': 'bind', 'source': source, 'target': target,
                       'read_only': True, 'bind': {'create_host_path': False}})
    return {'services': {'pay': {'environment': {
        'LND_REST_URL': url, 'LND_REST_INSECURE': insecure,
        'LND_TLS_CERT_PATH': '/test-lnd/tls.cert',
        'LND_MACAROON_PATH': '/test-lnd/admin.macaroon',
    }, 'volumes': mounts}}}


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else 'bolt12-pay'
    try:
        result = subprocess.run(['docker', 'inspect', '--type', 'container', name],
                                capture_output=True, text=True, check=True)
        print(json.dumps(configuration(json.loads(result.stdout)[0]), indent=2))
    except subprocess.CalledProcessError:
        sys.exit('Cannot inspect source container. Check Docker access and the container name (default: bolt12-pay).')
    except (ValueError, KeyError, IndexError) as exc:
        sys.exit(str(exc))


if __name__ == '__main__':
    main()
