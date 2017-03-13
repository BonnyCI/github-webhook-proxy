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
import logging
import sys
from wsgiref.simple_server import make_server

import webob
import webob.dec

LOG = logging.getLogger(__name__)
PORT = 9995


def application(request, body):
    if request.path != '/':
        raise webob.exc.HTTPNotFound()

    if request.method != 'POST':
        raise webob.exc.HTTPMethodNotAllowed()

    LOG.info(request.body)

    return webob.Response(status_code=200,
                          charset='utf-8',
                          content_type='application/text',
                          body=body.encode('utf-8'))

# class Handler(http.server.SimpleHTTPRequestHandler):
#
#     def do_POST(self):
#         if self.path == '/':
#             c_length = int(self.headers.get('Content-Length'))
#             c_type = self.headers.get('Content-Type', 'application/text')
#             data = self.rfile.read(length)
#             LOG.info(data)
#             self.send_response(200)
#             self.send_header('Content-Type', 'application/text')
#             self.end_headers()
#             self.wfile.write('Found Response'.encode('utf-8'))
#         else:
#             self.send_error(404, 'Not Found'.encode('utf-8'))
#

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()

    parser.add_argument('-p', '--port',
                        dest='port',
                        default=9995,
                        help='The port to listen on')

    parser.add_argument('-b', '--bind',
                        dest='bind',
                        default='127.0.0.1',
                        help='The ip to bind to')

    parser.add_argument('-t', '--text',
                        dest='text',
                        default='Responder Success',
                        help='The body to respond with')

    opts = parser.parse_args()

    app = webob.dec.wsgify(application, args=(opts.text,))
    httpd = make_server(opts.bind, int(opts.port), app)
    # httpd = http.server.HTTPServer((), Handler)
    LOG.info("Listening on %s:%d", opts.bind, int(opts.port))
    httpd.serve_forever()
