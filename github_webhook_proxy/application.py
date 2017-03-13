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
import hmac
import logging
import os
import platform
import signal
import sys

import aiohttp
import aiohttp.web
import ipaddress
import yaml

from github_webhook_proxy import version

ALLOWED_HEADERS = set([
    'Content-Type',
    'Content-Length',
    'X-Github-Event',
    'X-Hub-Signature'
])

GITHUB_META_URL = 'https://api.github.com/meta'

USER_AGENT = "github-webhook-proxy/{} aiohttp/{} {}/{}".format(
    version.version_string,
    aiohttp.__version__,
    platform.python_implementation(),
    platform.python_version())

LOG = logging.getLogger(__name__)


class GithubWebhookProxy:

    def __init__(self, config_file, loop=None):
        self.loop = loop or asyncio.get_event_loop()
        self.app = aiohttp.web.Application(loop=self.loop)
        self.app.router.add_post('/', self.handle_event)
        self.config_file = config_file

        self.load_config()

    def validate_signature(self, request):
        key = self.config.get('webhook_key')
        signature = request.headers.get('X-Hub-Signature')

        if key and not signature:
            raise web.HTTPForbidden()

        elif signature and not key:
            raise web.HTTPForbidden()

        elif key:
            digest, value = signature.split('=')

            if digest != 'sha1':
                raise web.HTTPForbidden()

            mac = hmac.new(key, msg=request.body, digestmod=hashlib.sha1)

            if not hmac.compare_digest(mac.hexdigest(), value):
                raise web.HTTPForbidden()

    def validate_ip(self, request):
        # request_ip = ipaddress.ip_address(request.client_addr.decode('utf-8'))
        # hook_blocks = requests.get(GITHUB_META_URL).json()['hooks']
        pass

    async def handle_event(self, request):
        self.validate_signature(request)
        self.validate_ip(request)

        headers = {'User-Agent': USER_AGENT}
        waiting = []

        for header in ALLOWED_HEADERS:
            try:
                headers[header] = request.headers[header]
            except KeyError:
                pass

        event_type = request.headers.get('X-Github-Event')
        request_body = await request.read()

        async with aiohttp.ClientSession(loop=self.loop) as session:
            for client_config in self.config.get('clients', []):
                url = client_config.get('url')
                events = client_config.get('events')

                if not url:
                    continue
                if events is not None and event_type not in events:
                    continue

                resp = session.post(url, data=request_body, headers=headers)
                waiting.append(resp)

            responses = await asyncio.gather(*waiting,
                                             loop=self.loop,
                                             return_exceptions=True)

        for resp in responses:
            if isinstance(resp, client.ClientResponse):
                resp_text = await resp.text()

                if resp.status == 200:
                    LOG.debug("Success: %s", resp_text)
                else:
                    LOG.info("Failure: %d, %s", resp.status, resp_text)

            elif isinstance(resp, errors.ClientOSError):
                LOG.warn(resp)

            else:
                LOG.warn("Unknown return: %s" % resp)

        if event_type == 'ping':
            return aiohttp.web.Response(text='pong')
        else:
            return aiohttp.web.Response(text='Hello world')

    def load_config(self):
        with open(self.config_file, 'r') as f:
            self.config = yaml.safe_load(f) or {}


def initialize_application(argv=None):
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--config',
                        dest='config',
                        default=os.environ.get('GWP_CONFIG_FILE'),
                        required=True,
                        help='Configuration file')

    opts = parser.parse_args(sys.argv[1:] if argv is None else argv)

    if not os.path.exists(opts.config):
        LOG.error("Config file does not exist {}".format(opts.config))
        return

    return GithubWebhookProxy(opts.config)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    app = initialize_application()

    def sig_handler():
        LOG.info("Reloading configuration from %s", app.config_file)
        app.load_config()

    if app:
        app.loop.add_signal_handler(signal.SIGHUP, sig_handler)
        aiohttp.web.run_app(app.app, host='127.0.0.1', port=8080)
