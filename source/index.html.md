---
title: AdBack API Reference

language_tabs: # must be one of https://git.io/vQNgJ
  - php
  - python
  - ruby
  - shell
  - twig
  - java


toc_footers:
  - <a href='https://www.adback.co/en/register/'>Sign Up for a Developer token</a>
  - <a href='https://www.adback.co/en/admin/api/'>Claim your token here, must be logged</a>
  - <a href='https://github.com/tripit/slate'>Documentation Powered by Slate</a>

includes:
  - errors

search: true
---

# Introduction

Welcome to the AdBack API documentation! You can use our API to access AdBack API endpoints, which can get non blockable URL and names for your analytics tags.

We have language bindings in PHP, Shell, Ruby, Java, and Python! You can view code examples in the dark area to the right, and you can switch the programming language of the examples with the tabs in the top right.

To fight back Adblock Easylist maintainers who chose to completely block any third party script on some websites, Adback needs to change the way it has been working till now.

The main issue is that the use of dummy domains and encrypted data has led Easylist to block everything that isn’t related to particular website, as they couldn’t find a way to block only AdBack. 

So, to recover its full capacities, AdBack needs to be a part of the only domain that is not blockable without damaging your website's’ functionality: your website domain.

## How it works ?

To do that, we must work together to bring AdBack into your infrastructure. These changes are divided into 3 steps:
 
* Integrating the full AdBack script into your page

* Adding an endpoint for AdBack scripts

* Acting as a proxy to transmit the AdBack data from your page to our servers through your infrastructure

![AdBack schema](/images/proxy_how.png)

### 1) Integrate AdBack full script in your pages

Instead of integrating a simple script that calls the full one, you will need to add the full AdBack script to your page. Thus the first calls are not blockable, as they are part of the page code.

This full script needs to be served by your servers, stored in cache for few hours, and updated regularly from our latest available scripts on AdBack servers API. 

For example: a cron every 3 hours storing the script in a Redis cache will do it well.

### 2) Adding an endpoint for AdBack scripts

The way AdBack is working: it needs to communicate with our servers to compute data, get correct scripts data, and serve related ads. As external calls could be blocked, we need to get this data through your servers, through an endpoint designed specifically for AdBack.

This endpoint needs to be a part of your website, on your main domain, and not on a subdomain as it could be easily blocked. As well, the endpoint url must be on the top level of your domain as an url pattern could be blocked as well.

For example, if your website is hosted on https://www.website.com, the best endpoint format could be https://www.website.com/randomword. 

To add an extra layer of security, we could plan an automatic endpoint name change, like would do Google Authenticator, preventing Adblock to block this call.

The script name in the generated script will be as well modified in a way it should not appear directly, as it could be automatically found and blocked by a regexp using tool.

### 3) Acting as a proxy

With the help of the newly created endpoint, we will gather data from your AdBlock users, send it to this endpoint and, through your servers, transmit it back to our AdBack servers. The response will be also returned to the user through your server after processing.

<aside class="info">AdBack proxy is an experimental feature that require activation from an AdBack administrator. If you want to use our proxy feature, please contact us at "support@adback.co".</aside>

# Implement AdBack

## 1) Configure cron update file

> sample script

```php
<?php

/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host');

$json = json_decode(file_get_contents('https://adback.co/api/script/me/full?access_token=[token]'), true);
/** @var array $scriptElements */
foreach ($json['script_codes'] as $type => $data) {
    $cache->hSet('adback_proxy', $type.'_code', $data['code']);
}
$cache->expire('adback_proxy', 60 * 60 * 6);
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
script_elements = requests.get('https://adback.co/api/script/me/full?access_token=[token]').json()
for (key, value) in script_elements['script_codes'].items():
    r_server.hset('adback_proxy', key+'_code', value['code'].encode("utf8"))
r_server.expire('adback_proxy', 60 * 60 * 6)

```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```

```ruby
require "redis"
require "json"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => "HOST")
script = open('https://adback.co/api/script/me/full?access_token=[token]').read
script_elements = JSON.parse(script)
script_elements['script_codes'].each do |key, value|
  cache.hset('adback_proxy', key+'_code', value['code'])
end
cache.expire('adback_proxy', 60 * 60 * 6)
```

```shell
# curl command

curl -X "GET" 'https://adback.co/api/script/me/full?access_token="token"'
```

```twig
# Launch the Symfony command to refesh the tags

$ php app/console adback:api-client:refresh-tag
```

> The above API call returns JSON structured like this:

```json
{
	"script_codes": {
		"analytics": {
			"script_name": "scriptname",
			"type": "analytics",
			"code": "(function e(t,n,r){...})"
        },
		"message": {
			"script_name": "scriptname",
			"type": "message",
			"code": "(function e(t,n,r){...})"
        },
		"banner": {
			"script_name": "scriptname",
			"type": "banner",
			"code": "(function e(t,n,r){...})"
        },	
		"catcher": {
			"script_name": "scriptname",
			"type": "catcher",
			"code": "(function e(t,n,r){...})"
        },
		"product": {
			"script_name": "scriptname",
			"type": "product",
			"code": "(function e(t,n,r){...})"
        },
		"iab_banner": {
			"script_name": "scriptname",
			"type": "iab_banner",
			"code": "(function e(t,n,r){...})"
        }
	}
}
```

In order for the scripts to be updated, you must run a script regularly that will get the script code from our AdBack servers and store it in your cache system. You will find there examples on how to do it with different technologies.

### Code logic:

* connect to your cache provider to limit api calls (here Redis)

* call AdBack API to get tags information 

* cache all information

* set cache expiry time to 6 hours

### HTTP Request:

`GET https://adback.co/api/script/me/full`

### Query Parameters:

Parameter | Required | Description
--------- | -------- | -----------
access_token | Yes | Personal token for authentication, [here](https://www.adback.co/en/admin/api/) you can get your token

<aside class="warning">You should setup cron task or service to refresh tag every 6 hours</aside>

## 2) Integrate AdBack full script in your pages

> Sample script:

```php

<?php
/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host', 'port');

$analyticsScriptCode = '';
if ($cache->has('adback_proxy')) {
    $codes = $cache->hGetAll('adback_proxy');
    foreach ($codes as $code)
    {
        /* display tag */
        echo "<script>$code</script>";
    }
}
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
if r_server.exists('adback_proxy'):
    codes = r_server.hgetall('adback_proxy')
    
    for code in codes:
        print "<script>" + code + "</script>"
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```

```ruby
require "redis"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => "HOST")
if cache.exists('adback_proxy')
  codes = cache.hgetall('adback_proxy');
  for code in codes
    puts "<script>#{code}</script>"
  end
end
```

```shell
# bash script to test api consumption
$ wget https://raw.githubusercontent.com/adback-anti-adblock-solution/adback-bash-refresh/master/adback-refresh-tags

$ chmod +x adback-refresh-tags

# display product flow tag with option -p and -html
$ ./adback-refresh-tags "token" -p -html
```

```twig
{{ adback_generate_scripts() }}
```

You must use your favorite tools or template engine to recover the script code from the previous step and insert it into your page.

### Code logic:

* connect to your cache provider (here Redis)

* get scripts codes

* generate and display tag

## 3) Configure proxy endpoint

> Using your webserver

> Nginx

```nginx
location /proxyname {
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    rewrite ^/proxy/(.*)$ /proxyname.js/$1 break;
    proxy_pass http://hosted.adback.co;
}
```

> Apache 2

```apache2
ProxyPreserveHost On
ProxyRequests Off
ProxyAddHeaders On
ProxyPass /proxyname http://hosted.adback.co/scriptname.js
ProxyPassReverse /proxyname  http://hosted.adback.co/scriptname.js
```

> Sample script:

```php
//proxy.php
<?php

/*
 * Configuration
 */

// Destination URL: Where this proxy leads to.
// Replace scriptname.js with one of your endpoints !
$destinationURL = 'http://hosted.adback.co/scriptname.js';

/*--------------------------------------------------------------/
| PROXY.PHP                                                     |
| Created By: Évelyne Lachance                                  |
| Contact: eslachance@gmail.com                                 |
| Source: http://github.com/eslachance/php-transparent-proxy	|
| Description: This proxy does a POST or GET request from any   |
|         page on the authorized domain to the defined URL      |
/--------------------------------------------------------------*/

// Credits to Chris Hope (http://www.electrictoolbox.com/chris-hope/) for this function.
// http://www.electrictoolbox.com/php-get-headers-sent-from-browser/
if (!function_exists('getallheaders')) {
    function getallheaders() {
        $headers = array();
        foreach ($_SERVER as $key => $value) {
            if (substr($key, 0, 5) == 'HTTP_') {
                $headers[str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))))] = $value;
            } elseif ($key == 'CONTENT_TYPE') {
                $headers[str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower($key))))] = $value;
            }
        }
        return $headers;
    }
}
// Figure out requester's IP to ship it to X-Forwarded-For
$ip = '';
if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
    $ip = $_SERVER['HTTP_CLIENT_IP'];
} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
} else {
    $ip = $_SERVER['REMOTE_ADDR'];
}

$currentUrl = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' ? 'https' : 'http' ). "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";

$params = '';
if (preg_match(sprintf('#/%s(?<params>/.+)#', preg_quote(basename($_SERVER["SCRIPT_FILENAME"]), '#')), $currentUrl, $matches)) {
    $params = $matches['params'];
} elseif (preg_match(sprintf('#/%s(?<params>/.+)#', preg_quote(basename($_SERVER["SCRIPT_NAME"]), '#')), $currentUrl, $matches)) {
    $params = $matches['params'];
}

$_SERVER['HTTP_REFERER'] = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : $currentUrl;

$method = $_SERVER['REQUEST_METHOD'];
if ($method == "GET") {
    $data=$_GET;
} elseif ($method=="POST" && count($_POST)>0) {
    $data=$_POST;
} else {
    $data = file_get_contents("php://input");
}
$response = proxy_request($destinationURL, $data, $method, $params, $ip);
$headerArray = explode("\r\n", $response['header']);
$is_chunked = false;
foreach($headerArray as $headerLine) {
    if (strtolower($headerLine) == "transfer-encoding: chunked") {
        $is_chunked = true;
    }
}
$contents = $response['content'];
if ($is_chunked) {
    $decodedContents = @decode_chunked($contents);

    if (strlen($decodedContents)) {
        $contents = $decodedContents;
    }
}

foreach ($headerArray as $header) {
    if (
        strpos(strtolower($header), 'transfer-encoding') === false
    ) {
        header($header, true);
    }
}

echo $contents;

function proxy_request($url, $data, $method, $params, $ip) {
// Based on post_request from http://www.jonasjohn.de/snippets/php/post-request.htm
    $req_dump = print_r($data, TRUE);

    $url = parse_url($url);

    // Convert the data array into URL Parameters like a=b&foo=bar etc.
    if ($method == "GET")  {
        $data = http_build_query($data);

        // Add GET params from destination URL
        if (isset($parsedUrl['query'])) {
            $data = $data . $url["query"];
        }
    } elseif ($method=="POST" && count($_POST)>0) {
        $data = http_build_query($data);

        // Add GET params from destination URL
        if (isset($parsedUrl['query'])) {
            $data = $data . $url["query"];
        }
    } else {
        $data = $data;
    }

    $datalength = strlen($data);

    if ($url['scheme'] != 'http') {
        die('Error: Only HTTP request are supported !');
    }

    // extract host and path:
    $host = $url['host'];
    $path = $url['path'].$params;
    $port = isset($url['port']) ? $url['port'] : ($url['scheme'] == 'https' ? '443' : '80');

    $fp = fsockopen($host, $port, $errno, $errstr, 30);

    if ($fp){
        // send the request headers:
        if ($method == "POST") {
            $callback = "POST $path HTTP/1.1\r\n";
        } else {
            $callback = "GET $path?$data HTTP/1.1\r\n";
        }
        $callback .= "Host: $host\r\n";

        $callback .= "X-Forwarded-For: $ip\r\n";
        $callback .= "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n";

        $requestHeaders = getallheaders();

        foreach ($requestHeaders as $header => $value) {
            $lowerHeader = strtolower($header);
            if (
                $lowerHeader !== "connection"
                && $lowerHeader !== "host"
                && $lowerHeader !== "content-length"
                && $lowerHeader !== "content-type"
            ) {
                $callback .= "$header: $value\r\n";
            }
        }

        if ($method == "POST" && isset($requestHeaders['Content-Type'])) {
            $callback .= "Content-Type: ".$requestHeaders['Content-Type']."\r\n";
            $callback .= "Content-length: ".$datalength."\r\n";
        }

        $callback .= "Connection: close\r\n\r\n";
        if ($datalength) {
            $callback .= "$data\r\n\r\n";
        }

        fwrite($fp, $callback);

        $result = '';
        while (!feof($fp)) {
            // receive the results of the request
            $result .= fgets($fp, 128);
        }
    }
    else {
        return array(
            'status' => 'err',
            'error' => "$errstr ($errno)"
        );
    }

    // close the socket connection:
    fclose($fp);

    // split the result header from the content
    $result = explode("\r\n\r\n", $result, 2);
    $header = isset($result[0]) ? $result[0] : '';
    $content = isset($result[1]) ? $result[1] : '';

    // return as structured array:
    return array(
        'status' => 'ok',
        'header' => $header,
        'content' => $content
    );
}

// Credits to @flowfree (http://stackoverflow.com/users/1396314/flowfree) for this function.
// http://stackoverflow.com/questions/10793017/how-to-easily-decode-http-chunked-encoded-string-when-making-raw-http-request
function decode_chunked($str) {
    for ($res = ''; !empty($str); $str = trim($str)) {
        $pos = strpos($str, "\r\n");
        $len = hexdec(substr($str, 0, $pos));
        $res.= substr($str, $pos + 2, $len);
        $str = substr($str, $pos + 2 + $len);
    }
    return $res;
}

?>
```

```python
//proxy2.py Untested !
// Source: https://github.com/inaz2/proxy2
# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8080
    server_address = ('::1', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
    test()
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```

```ruby
//proxy.rb Untested !
// Source: https://gist.githubusercontent.com/torsten/74107/raw/f3c666d9b7bf4ba1a6bbd5f4335e010beaed13d3/proxy.rb
#!/usr/bin/env ruby
# A quick and dirty implementation of an HTTP proxy server in Ruby
# because I did not want to install anything.
# 
# Copyright (C) 2009-2014 Torsten Becker <torsten.becker@gmail.com>
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'socket'
require 'uri'


class Proxy  
  def run port
    begin
      # Start our server to handle connections (will raise things on errors)
      @socket = TCPServer.new port
      
      # Handle every request in another thread
      loop do
        s = @socket.accept
        Thread.new s, &method(:handle_request)
      end
      
    # CTRL-C
    rescue Interrupt
      puts 'Got Interrupt..'
    # Ensure that we release the socket on errors
    ensure
      if @socket
        @socket.close
        puts 'Socked closed..'
      end
      puts 'Quitting.'
    end
  end
  
  def handle_request to_client
    request_line = to_client.readline
    
    verb    = request_line[/^\w+/]
    url     = request_line[/^\w+\s+(\S+)/, 1]
    version = request_line[/HTTP\/(1\.\d)\s*$/, 1]
    uri     = URI::parse url
    
    # Show what got requested
    puts((" %4s "%verb) + url)
    
    to_server = TCPSocket.new(uri.host, (uri.port.nil? ? 80 : uri.port))
    to_server.write("#{verb} #{uri.path}?#{uri.query} HTTP/#{version}\r\n")
    
    content_len = 0
    
    loop do      
      line = to_client.readline
      
      if line =~ /^Content-Length:\s+(\d+)\s*$/
        content_len = $1.to_i
      end
      
      # Strip proxy headers
      if line =~ /^proxy/i
        next
      elsif line.strip.empty?
        to_server.write("Connection: close\r\n\r\n")
        
        if content_len >= 0
          to_server.write(to_client.read(content_len))
        end
        
        break
      else
        to_server.write(line)
      end
    end
    
    buff = ""
    loop do
      to_server.read(4048, buff)
      to_client.write(buff)
      break if buff.size < 4048
    end
    
    # Close the sockets
    to_client.close
    to_server.close
  end
  
end


# Get parameters and start the server
if ARGV.empty?
  port = 8008
elsif ARGV.size == 1
  port = ARGV[0].to_i
else
  puts 'Usage: proxy.rb [port]'
  exit 1
end

Proxy.new.run port
```

```shell
Please contact our support team at "support@adback.co" to configure adback with Shell
```

```twig
Your Symfony extension should handle proxy without any change from you
```

You could choose between two ways of configuring your endpoint: using your webserver or a programming language

These scripts are for example purpose only. 

To help you create your own proxy file, please send us the following information at support@adback.co: 

* Which webserver software are you using? (Apache, Nginx, ...) 

* Which programming language are you using? (PHP, Java, Python, ...) 

* Which cache technology are you using? (Redis, Memcached, MySQL database, ...) 

You can download configuration file from adback back-office for <a href="https://www.adback.co/en/integration/configuration/apache2">apache2</a> and <a href="https://www.adback.co/en/integration/configuration/nginx">nginx</a> (Must be logged) 

<aside class="warning">Only php proxy and nginx server configuration have been tested for now. Feel free to tell us if others work for you.</aside>

### Code logic:

* Receive call from your users via the tag integrated on your pages

* Transmit call to AdBack servers 

* Receive response from AdBack servers

* Transmit response to your users


# AdBack tags

## 1) Get script names and URL

> Sample script:

```php
<?php

/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host');

$scriptElements = json_decode(file_get_contents('https://adback.co/api/script/me?access_token=[token]'), true);
/** @var array $scriptElements */
foreach ($scriptElements as $key => $value) {
    $cache->hSet('scriptElement', $key, $value);
}
$cache->expire('scriptElement', 60 * 60 * 6);
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
script_elements = requests.get('https://adback.co/api/script/me?access_token=[token]').json()
for (key, value) in script_elements.items():
    r_server.hset('script_element', key, value.encode("utf8"))
r_server.expire('script_element', 60 * 60 * 6)
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```

```ruby
require "redis"
require "json"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => "HOST")
script = open('https://adback.co/api/script/me?access_token=[token]').read
script_elements = JSON.parse(script)
script_elements.each do |key, value|
  cache.hset('script_element', key, value)
end
cache.expire('script_element', 60 * 60 * 6)
```

```shell
# curl command

curl -X "GET" 'https://adback.co/api/script/me?access_token="token"'
```

```twig
# Launch the Symfony command to refesh the tags

$ php app/console adback:api-client:refresh-tag
```

> The above API call returns JSON structured like this:

```json
{
  "analytics_domain": "example.url.com",
  "analytics_script": "scriptname",
  "message_domain": "example.url.com",
  "message_script": "scriptname",
  "autopromo_banner_domain": "example.url.com",
  "autopromo_banner_script": "scriptname",
  "product_domain": "example.url.com",
  "product_script": "scriptname",
  "iab_banner_domain": "example.url.com",
  "iab_banner_script": "scriptname"
}
```

AdBack provides 4 different scripts that you can generate and display from your server.

Here is the first step to implement AdBack solution.

Call AdBack API to get script names and URL, store it in your preferred local cache provider.

### Code logic:

* connect to your cache provider to limit api calls (here Redis)

* call AdBack API to get tags information 

* cache all information

* set cache expiry time to 6 hours

### HTTP Request:

`GET https://adback.co/api/script/me`

### Query Parameters:

Parameter | Required | Description
--------- | -------- | -----------
access_token | Yes | Personal token for authentication, [here](https://www.adback.co/en/admin/api/) you can get your token

<aside class="notice">
If API doesn't return all script names or URL, please check your configuration <a href="https://www.adback.co/en/integration/admin/activation">here</a> and make sure all tags are activated.
</aside>

<aside class="warning">You should setup cron task or service to refresh tag every 6 hours</aside>

## 2) Analytics script

> Sample script:

```php

<?php
/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host', 'port');

$analyticsScriptCode = '';
if ($cache->has('scriptElement')) {
    $scriptElements = $cache->hGetAll('scriptElement');
    $analyticsDomain = $scriptElements['analytics_domain'];
    $analyticsScript = $scriptElements['analytics_script'];
    
    $analyticsScriptCode = <<<EOS
        (function (a,d){var s,t;s=d.createElement('script');
        s.src=a;s.async=1;
        t=d.getElementsByTagName('script')[0];
        t.parentNode.insertBefore(s,t);
        })("https://$analyticsDomain/$analyticsScript.js", document);
EOS;
}

/* display tag */
echo "<script>$analyticsScriptCode</script>";
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
analytics_script_code = ''
if r_server.exists('script_element'):
    script_elements = r_server.hgetall('script_element')
    analytics_domain = script_elements['analytics_domain']
    analytics_script = script_elements['analytics_script']
    
    analytics_script_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://%s/%s.js\", document);
    """ % (analytics_domain, analytics_script)

''' display tag '''
print "<script>%s</script>" % analytics_script_code
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```

```ruby
require "redis"
require "json"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => "HOST")
analytics_script_code = '';
if cache.exists('script_element')
  script_elements = cache.hgetall('script_element');
  analytics_domain = script_elements['analytics_domain'];
  analytics_script = script_elements['analytics_script'];
    
  analytics_script_code = """
  (function (a,d){var s,t;s=d.createElement('script');
  s.src=a;s.async=1;
  t=d.getElementsByTagName('script')[0];
  t.parentNode.insertBefore(s,t);
  })(\"https://#{analytics_domain}/#{analytics_script}.js\", document);
  """
end

# display tag
puts "<script>#{analytics_script_code}</script>"
```

```shell
# bash script to test api consumption
$ wget https://raw.githubusercontent.com/adback-anti-adblock-solution/adback-bash-refresh/master/adback-refresh-tags

$ chmod +x adback-refresh-tags

# display analytics tag with option -a and -html
$ ./adback-refresh-tags "token" -a -html
```

```twig
{{ adback_generate_scripts() }}
```

AdBack analytics provide unique data on adblock users (blocked pages, types of adblockers, Ghostery users, acceptable ads Eyeo users, precise repartition on desktop and mobile adblocker users, etc)

### Code logic:

* connect to your cache provider (here Redis)

* get script names and URL

* generate and display tag

### Single page application

You must call javascript function `adback.API().send()` to count your one page views after the analytics AdBack tag.

<aside class="notice">If you run single page application, don't forget to call javascript function `adback.API().send()` to count your pages views</aside>


## 3) Message script


> Sample script:

```php
<?php

/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host', 'port');

$messageCode = '';
if ($cache->has('scriptElement')) {
    $scriptElements = $cache->hGetAll('scriptElement');
    if (isset($scriptElements['message_script'])) {
        $messageDomain = $scriptElements['message_domain'];
        $messageScript = $scriptElements['message_script'];
        $messageCode = <<<EOS
        (function (a,d){var s,t;s=d.createElement('>script');
        s.src=a;s.async=1;
        t=d.getElementsByTagName('script')[0];
        t.parentNode.insertBefore(s,t);
        })("https://$messageDomain/$messageScript.js", document);
EOS;
    }
}

/* display tag */
echo "<script>$messageCode</script>";

/* script you can set to display message on certain pages of your site */
echo "<script>var adback = adback || {}; adback.perimeter = 'perimeter1';</script>";
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
message_code = ''
if r_server.exists('script_element'):
    script_elements = r_server.hgetall('script_element')
    message_domain = script_elements['message_domain']
    message_script = script_elements['message_script']

    message_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://%s/%s.js\", document);
    """ % (message_domain, message_script)

''' display tag '''
print "<script>%s</script>" % message_code

''' script you can set to display message on certain pages of your site '''
print "<script>var adback = adback || {}; adback.perimeter = 'perimeter1';</script>"
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```

```ruby
require "redis"
require "json"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => 'host')
message_code = '';
if cache.exists('script_element')
  script_elements = cache.hgetall('script_element');
  unless script_elements['message_script'].nil?
    message_domain = script_elements['message_domain'];
    message_script = script_elements['message_script'];
    message_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://#{message_domain}/#{message_script}.js\", document);
    """
  end
end

# display tag
puts "<script>#{message_code}</script>"

# script you can set to display message on certain pages of your site
puts "<script>var adback = adback || {}; adback.perimeter = 'perimeter1';</script>"
```

```shell
# bash script to test api consumption
$ wget https://raw.githubusercontent.com/adback-anti-adblock-solution/adback-bash-refresh/master/adback-refresh-tags

$ chmod +x adback-refresh-tags

# display message tag with option -c and -html
$ ./adback-refresh-tags "token" -c -html
```

```twig
<!-- Make sure to include it only once -->
{{ adback_generate_scripts() }}
```

The custom message allows to dialog with adblock users, through a smart paywall able tu push several alternatives (whilsting tutorial, video watching).

### Code logic:

* connect to your cache provider (here Redis)

* get script names and URL

* generate javascript tag

* display tag

* [optional] create adback.perimeter variable and set the perimeter

* [optional] add custom class to your `<body>` if CONTENT LIMITATION is check

### Script Parameters:

Parameter | Required | Description
--------- | -------- | -----------
adback.perimeter | No | Variable you can set to display message on certain pages of your site, perimeter can be configured <a href="https://www.adback.co/en/monitoring/custom">here</a>

Back office configuration example:

![message perimeter](/images/perimeter_message.png)

### Specific format - restriction content message:

You can display text inside the article content and show only the 400 first character of an article for example.

> Restricted body example:

```html
<!-- article example -->
<body class="test_restriction_content">
    Section 1.10.32 du "De Finibus Bonorum et Malorum" de Ciceron (45 av. J.-C.)

    "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, 
    totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. 
    Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui 
    ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, 
    adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. 
    Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi 
    consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, 
    vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?"
</body>
```

![content restriction](/images/content_restriction.png)

<aside class="notice">You should configure your message after tag installation, <a href="https://www.adback.co/en/monitoring/custom">here</a>
you can see a preview of all your messages and publish / unpublish it</aside>


## 4) Autopromo banner script

> Sample script:

```php
<?php

/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host', 'port');

$autopromoBannerCode = '';
if ($cache->has('scriptElement')) {
    $scriptElements = $cache->hGetAll('scriptElement');
    if (isset($scriptElements['autopromo_banner_script'])) {
    $autopromoBannerDomain = $scriptElements['autopromo_banner_domain'];
    $autopromoBannerScript = $scriptElements['autopromo_banner_script'];
    $autopromoBannerCode = <<<EOS
        (function (a,d){var s,t;s=d.createElement('script');
        s.src=a;s.async=1;
        t=d.getElementsByTagName('script')[0];
        t.parentNode.insertBefore(s,t);
        })("https://$autopromoBannerDomain/$autopromoBannerScript.js", document);
EOS;
    }
}

/* add div where you want to display your banner with placement 'header_728x90' */
echo "<div data-tag='header_728x90'></div>";

/* add div where you want to display your banner with placement 'side_300x250_actu' */
echo "<div data-tag='side_300x250_actu'></div>";

/* display tag */
echo "<script>$autopromoBannerCode</script>";
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
autopromo_banner_code = ''
if r_server.exists('script_element'):
    script_elements = r_server.hgetall('script_element')
    autopromo_banner_domain = script_elements['autopromo_banner_domain']
    autopromo_banner_script = script_elements['autopromo_banner_script']

    autopromo_banner_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://%s/%s.js\", document);
    """ % (autopromo_banner_domain, autopromo_banner_script)

'''add div where you want to display your banner with placement 'header_728x90' '''
print "<div data-tag='header_728x90'></div>"

'''add div where you want to display your banner with placement 'side_300x250_actu' '''
print "<div data-tag='side_300x250_actu'></div>"

'''display tag'''
print "<script>%s</script>" % autopromo_banner_code
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```


```ruby
require "redis"
require "json"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => "HOST")
autopromo_banner_code = '';
if cache.exists('script_element')
  script_elements = cache.hgetall('script_element');
  unless script_elements['autopromo_banner_script'].nil?
    autopromo_banner_domain = script_elements['autopromo_banner_domain'];
    autopromo_banner_script = script_elements['autopromo_banner_script'];
    autopromo_banner_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://#{autopromo_banner_domain}/#{autopromo_banner_script}.js\", document);
    """
  end
end

# add div where you want to display your banner with placement 'header_728x90'
puts "<div data-tag='header_728x90'></div>"

# add div where you want to display your banner with placement 'side_300x250_actu'
puts "<div data-tag='side_300x250_actu'></div>"

# display tag
puts "<script>#{autopromo_banner_code}</script>"
```

```shell
# bash script to test api consumption
$ wget https://raw.githubusercontent.com/adback-anti-adblock-solution/adback-bash-refresh/master/adback-refresh-tags

$ chmod +x adback-refresh-tags

# display autopromo banner tag with option -b and -html
$ ./adback-refresh-tags "token" -b -html
```

```twig
<!-- add div where you want to display your banner with placement 'header_728x90' -->
<div data-tag='header_728x90'></div>

<!-- add div where you want to display your banner with placement 'side_300x250_actu' -->
<div data-tag='side_300x250_actu'></div>

{{ adback_generate_autopromo_banner_script() }}
```

Our auto-promo banners permit to display ads for premium campaigns or your own content on blocked ads placements.

![Autopromo](/images/autopromo.png)

### Code logic:

* connect to your cache provider (here Redis)

* get script names and URL

* generate and display tag with one placement / banner

### Script Parameters:

Parameter | Required | Description
--------- | -------- | -----------
placement | Yes | Variable you must set to display one banner, data-tag takes one placement and can be configured <a href="https://www.adback.co/en/autopromo/banners">here</a>

Back office configuration example:

![Autopromo perimeter](/images/autopromo_placement.png)

### Placement naming:

You should name your placement like back office example, location _ dimension _ campaign promo name,

`header_728x90  ou  side_300x250_actu`

Make sure this names match the back office configuration.

<aside class="notice">After tag installation, you must create new banner <a href="https://www.adback.co/en/autopromo/banners">here</a> for every placement that you integrate before.</aside>


## 5) Product flow script

> Sample script:

```php
<?php

/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host');

$productFlowCode = '';
if ($cache->has('scriptElement')) {
    $scriptElements = $cache->hGetAll('scriptElement');
    if (isset($scriptElements['product_script'])) {
        $productDomain = $scriptElements['product_domain'];
        $productScript = $scriptElements['product_script'];
        $productFlowCode = <<<EOS
        (function (a,d){var s,t;s=d.createElement('script');
        s.src=a;s.async=1;
        t=d.getElementsByTagName('script')[0];
        t.parentNode.insertBefore(s,t);
        })("https://$productDomain/$productScript.js", document);
EOS;
    }
}

/* display product flow script */
echo "<script>$productFlowCode</script>";
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
product_flow_code = ''
if r_server.exists('script_element'):
    script_elements = r_server.hgetall('script_element')
    product_domain = script_elements['product_domain']
    product_script = script_elements['product_script']

    product_flow_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://%s/%s.js\", document);
    """ % (product_domain, product_script)

'''add div where you want to display your banner with placement header_728x90'''
print "<div data-tag='header_728x90'></div>"

'''add div where you want to display your banner with placement side_300x250_actu'''
print "<div data-tag='side_300x250_actu'></div>"

'''display tag'''
print "<script>%s</script>" % product_flow_code
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```

```ruby
require "redis"
require "json"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => "HOST")
product_flow_code = '';
if cache.exists('script_element')
  script_elements = cache.hgetall('script_element');
  unless script_elements['product_script'].nil?
    product_domain = script_elements['product_domain'];
    product_script = script_elements['product_script'];
    product_flow_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://#{product_domain}/#{product_script}.js\", document);
    """
  end
end

# display tag
puts "<script>#{product_flow_code}</script>"

```

```shell
# bash script to test api consumption
$ wget https://raw.githubusercontent.com/adback-anti-adblock-solution/adback-bash-refresh/master/adback-refresh-tags

$ chmod +x adback-refresh-tags

# display product flow tag with option -p and -html
$ ./adback-refresh-tags "token" -p -html
```

```twig
{{ adback_generate_product_script() }}
```

Our product-flow displays automatically contextual ads on the blocked ads placements.

### Code logic:

* connect to your cache provider (here Redis)

* get script names and URL

* generate and display tag

<aside class="notice">You should contact our sales team to activate the product flow after tag installation at <a href="mailto:support@adback.co">support@adback.co</a></aside>

## 6) IAB banner script

> Sample script:

```php
<?php

/* here we use redis to cache api requests */
$cache = new Redis();
$cache->connect('host', 'port');

$iabBannerCode = '';
if ($cache->has('scriptElement')) {
    $scriptElements = $cache->hGetAll('scriptElement');
    if (isset($scriptElements['iab_banner_script'])) {
    $iabBannerDomain = $scriptElements['iab_banner_domain'];
    $iabBannerScript = $scriptElements['iab_banner_script'];
    $iabBannerCode = <<<EOS
        (function (a,d){var s,t;s=d.createElement('script');
        s.src=a;s.async=1;
        t=d.getElementsByTagName('script')[0];
        t.parentNode.insertBefore(s,t);
        })("https://$iabBannerDomain/$iabBannerScript.js", document);
EOS;
    }
}

/* add div where you want to display your banner with placement 'header_728x90' */
echo "<div data-iab-tag='header_728x90'></div>";

/* add div where you want to display your banner with placement 'side_300x250_actu' */
echo "<div data-iab-tag='side_300x250_actu'></div>";

/* display tag */
echo "<script>$iabBannerCode</script>";
```

```python
import redis
import requests

'''here we use redis to cache api requests'''
r_server = redis.Redis('host', 'port')
iab_banner_code = ''
if r_server.exists('script_element'):
    script_elements = r_server.hgetall('script_element')
    iab_banner_domain = script_elements['iab_banner_domain']
    iab_banner_script = script_elements['iab_banner_script']

    iab_banner_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://%s/%s.js\", document);
    """ % (iab_banner_domain, iab_banner_script)

'''add div where you want to display your banner with placement 'header_728x90' '''
print "<div data-iab-tag='header_728x90'></div>"

'''add div where you want to display your banner with placement 'side_300x250_actu' '''
print "<div data-iab-tag='side_300x250_actu'></div>"

'''display tag'''
print "<script>%s</script>" % iab_banner_code
```

```java
Please contact our support team at "support@adback.co" to configure adback with Java
```


```ruby
require "redis"
require "json"
require 'open-uri'

# here we use redis to cache api requests
cache = Redis.new(:host => "HOST")
iab_banner_code = '';
if cache.exists('script_element')
  script_elements = cache.hgetall('script_element');
  unless script_elements['iab_banner_script'].nil?
    iab_banner_domain = script_elements['iab_banner_domain'];
    iab_banner_script = script_elements['iab_banner_script'];
    iab_banner_code = """
    (function (a,d){var s,t;s=d.createElement('script');
    s.src=a;s.async=1;
    t=d.getElementsByTagName('script')[0];
    t.parentNode.insertBefore(s,t);
    })(\"https://#{iab_banner_domain}/#{iab_banner_script}.js\", document);
    """
  end
end

# add div where you want to display your banner with placement 'header_728x90'
puts "<div data-iab-tag='header_728x90'></div>"

# add div where you want to display your banner with placement 'side_300x250_actu'
puts "<div data-iab-tag='side_300x250_actu'></div>"

# display tag
puts "<script>#{iab_banner_code}</script>"
```

```shell
# bash script to test api consumption
$ wget https://raw.githubusercontent.com/adback-anti-adblock-solution/adback-bash-refresh/master/adback-refresh-tags

$ chmod +x adback-refresh-tags

# display iab banner tag with option -i and -html
$ ./adback-refresh-tags "token" -i -html
```

```twig
<!-- add div where you want to display your banner with placement 'header_728x90' -->
<div data-iab-tag='header_728x90'></div>

<!-- add div where you want to display your banner with placement 'side_300x250_actu' -->
<div data-iab-tag='side_300x250_actu'></div>

{{ adback_generate_iab_banner_script() }}
```

Our IAB banners permit to display ads for premium campaigns on blocked ads placements.

### Code logic:

* connect to your cache provider (here Redis)

* get script names and URL

* generate and display tag with one placement / banner

### Script Parameters:

Parameter | Required | Description
--------- | -------- | -----------
placement | Yes | Variable you must set to display one banner, data-iab-tag takes one placement and can be configured <a href="https://www.adback.co/en/iab-banners/banners">here</a>

Back office configuration example:

### Placement naming:

You should name your placement like back office example, location _ dimension _ campaign promo name,

`header_728x90  ou  side_300x250_actu`

Make sure this names match the back office configuration.

<aside class="notice">After tag installation, you must create new banner <a href="https://www.adback.co/en/iab-banners/banners">here</a> for every placement that you integrate before.</aside>
<aside class="warning">Take care that the container where you put the "data-iab-tag" div must not be blocked by adblock, otherwise no ads will be shown. Often containers with classes starting with "ad-" will be blocked.</aside>

### Wordpress placement creation

You can either modify the source code of your Wordpress template if you feel confident with it, and add the placement where you want:
`<div data-iab-tag='side_300x250_actu'></div>`
(Change the placement name of course)

Or you can create a new widget in your backoffice

* Go to the widgets management page from your Dashboard or Menu

![Widgets management](/images/wp_widgets_management.png)

![Widgets management meny](/images/wp_widgets_management_2.png)

* Select "Custom HTML"

![Custom HTML](/images/wp_widgets_custom_html.png)

* Depending on your wordpress template, select where you want the ad to appear, and click on "Add Widget"

![Widget location](/images/wp_widgets_location.png)

* Enter your placement code in the content, leave title blank and click "Save". Your placement code should look like this: 
`<div data-iab-tag='side_300x250_actu'></div>`
(Change the placement name of course)

![Widget placement_code](/images/wp_widgets_placement_code.png)

* Your ad should appear shortly after where you defined it.

