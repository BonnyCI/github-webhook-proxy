# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import argparse
import asyncio
import hashlib
import hmac
import logging
import os
import platform
import signal
import time

import aiohttp
import aiohttp.web
import ipaddress
import munch
import requests
import voluptuous
import yaml

from github_webhook_proxy import version

ALLOWED_HEADERS = set([
    'Content-Type',
    'Content-Length',
    'X-Github-Event',
    'X-Hub-Signature',
    'X-GitHub-Delivery',
])

GITHUB_META_URL = 'https://api.github.com/meta'
GITHUB_META_CACHE_TTL = 3600
GITHUB_META_CACHE_TIMEOUT = 30
USER_AGENT = "github-webhook-proxy/{} aiohttp/{} {}/{}".format(
    version.version_string,
    aiohttp.__version__,
    platform.python_implementation(),
    platform.python_version())
PROXY_TIMEOUT = 10
LOG = logging.getLogger(__name__)


class GithubWebhookProxy:

    def __init__(self, config_file, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.app = aiohttp.web.Application(loop=self.loop)
        self.app.router.add_post('/github-webhook/', self.handle_event)
        self.config_file = config_file
        self.hook_blocks = munch.Munch({
            'last_updated': None,
            'networks': [],
        })
        self.load_config()

    def validate_signature(self, request, request_body):
        key = self.config.get('webhook_key')
        signature = request.headers.get('X-Hub-Signature')

        if key and not signature:
            raise aiohttp.web.HTTPForbidden()

        elif signature and not key:
            raise aiohttp.web.HTTPForbidden()

        elif key:
            digest, value = signature.split('=')

            if digest != 'sha1':
                raise aiohttp.web.HTTPForbidden()

            key = key.encode("utf8")
            mac = hmac.new(key, msg=request_body, digestmod=hashlib.sha1)

            if not hmac.compare_digest(mac.hexdigest(), value):
                raise aiohttp.web.HTTPForbidden()

    def validate_ip(self, request_ip):
        if not self.config.get('validate_source_ips'):
            return
        now = time.monotonic()
        if (self.hook_blocks.last_updated is None or
                (now - self.hook_blocks.last_updated) > GITHUB_META_CACHE_TTL):
            resp = requests.get(GITHUB_META_URL,
                                timeout=GITHUB_META_CACHE_TIMEOUT)
            try:
                resp.raise_for_status()
            except Exception:
                LOG.exception("Failed calling into '%s'", GITHUB_META_URL)
                raise aiohttp.web.HTTPInternalServerError()
            hook_blocks = resp.json()['hooks']
            LOG.debug("Valid github hook cidrs: %s", hook_blocks)
            hook_blocks = [ipaddress.ip_network(h) for h in hook_blocks]
            self.hook_blocks.networks = hook_blocks
            self.hook_blocks.last_updated = time.monotonic()
        valid = False
        for netblock in self.hook_blocks.networks:
            if request_ip in netblock:
                valid = True
                break
        if not valid and self.config.get("allowed_ips"):
            for tmp_ip in self.config.get("allowed_ips", []):
                ip = ipaddress.ip_address(tmp_ip)
                if ip == request_ip:
                    valid = True
                    break
        if not valid:
            raise aiohttp.web.HTTPForbidden()

    async def proxy(self, request_body, event_type, headers):
        waiting = []
        waiting_urls = []
        async with aiohttp.ClientSession(loop=self.loop) as session:
            for client_config in list(self.config.get('clients', [])):
                url = client_config.get('url')
                events = client_config.get('events')

                if not url:
                    continue
                if events is not None and event_type not in events:
                    continue

                timeout = client_config.get("timeout", PROXY_TIMEOUT)
                resp = session.post(url, data=request_body,
                                    headers=headers, timeout=timeout)
                waiting.append(resp)
                waiting_urls.append(url)

            responses = await asyncio.gather(*waiting,
                                             loop=self.loop,
                                             return_exceptions=True)
        for i, resp in enumerate(responses):
            url = waiting_urls[i]
            if isinstance(resp, aiohttp.ClientResponse):
                resp_text = await resp.text()
                if resp.status == 200:
                    LOG.debug("Successfully proxied to '%s', %s, %s",
                              url, resp.status, resp_text)
                else:
                    LOG.warn("Failed proxy to '%s' %s, %s", url,
                             resp.status, resp_text)
            elif isinstance(resp, aiohttp.ClientConnectionError):
                LOG.warn("Client connection error: %s, %s", url, resp)
            elif isinstance(resp, aiohttp.ClientOSError):
                LOG.warn("Client os error: %s, %s", url, resp)
            else:
                LOG.warn("Unknown %s error from call to %s: %s",
                         type(resp), url, resp)

    def validate_event_type(self, request):
        event_type = request.headers.get('X-Github-Event')
        if not event_type:
            raise aiohttp.web.HTTPForbidden()
        return event_type

    async def handle_event(self, request):
        LOG.debug("Processing call from '%s'", request.remote)
        request_ip = ipaddress.ip_address(request.remote)
        self.validate_ip(request_ip)

        request_body = await request.read()
        self.validate_signature(request, request_body)
        event_type = self.validate_event_type(request)

        headers = {
            'User-Agent': USER_AGENT,
        }
        for header in ALLOWED_HEADERS:
            try:
                headers[header] = request.headers[header]
            except KeyError:
                pass

        LOG.debug("Received validated '%s' event from '%s'", event_type,
                  request_ip)
        LOG.debug(request_body)
        asyncio.ensure_future(self.proxy(request_body, event_type,
                                         headers), loop=self.loop)

        if event_type == 'ping':
            return aiohttp.web.Response(text='pong')
        else:
            return aiohttp.web.Response(text='')

    def load_config(self):
        with open(self.config_file, 'r') as f:
            config = yaml.safe_load(f) or {}
        validate(config)
        self.config = config


def initialize_application(opts):
    if not os.path.exists(opts.config):
        LOG.error("Config file does not exist {}".format(opts.config))
        return
    return GithubWebhookProxy(opts.config)


def validate(config):
    client = voluptuous.Schema({
        voluptuous.Required('url'): str,
        voluptuous.Optional('events'): list([str]),
        voluptuous.Optional("timeout"): int,
    }, extra=False)

    s = voluptuous.Schema({
        'webhook_key': str,
        voluptuous.Optional("allowed_ips"): list([str]),
        voluptuous.Optional('validate_source_ips'): bool,
        'clients': list([client]),
    }, extra=False)

    s(config)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config',
                        dest='config',
                        default=os.environ.get('GWP_CONFIG_FILE'),
                        required=True,
                        help='Configuration file')
    parser.add_argument("-p", "--port", dest='port',
                        default=8080, type=int,
                        help='Port to run proxy on (default=%(default)s)')
    parser.add_argument("-e", "--expose",
                        default=False, action="store_true",
                        help="Expose port on '0.0.0.0' vs '127.0.0.1'")
    parser.add_argument("-v", "--verbose", default=0,
                        action='count', help="Increase verbosity")

    opts = parser.parse_args()

    if opts.verbose == 0:
        logging.basicConfig(level=logging.WARN)
    elif opts.verbose == 1:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)

    app = initialize_application(opts)

    def sig_handler():
        LOG.info("Reloading configuration from %s", app.config_file)
        app.load_config()

    if app:
        app.loop.add_signal_handler(signal.SIGHUP, sig_handler)
        if opts.expose:
            host = "0.0.0.0"
        else:
            host = "127.0.0.1"
        aiohttp.web.run_app(app.app, host=host, port=opts.port)


if __name__ == '__main__':
    main()
