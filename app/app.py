from flask import Flask, request, Response, abort
import requests
from urllib.parse import unquote, urlparse
import re

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 2048 # 限制2048MB请求体
TIMEOUT = 300  # 请求超时时间

# 需要删除的敏感headers（完整Cloudflare相关头）
SENSITIVE_HEADERS = [
    'X-Forwarded-For', 'CF-Connecting-IP', 'CF-IPCountry',
    'CF-Ray', 'CF-Request-ID', 'CF-Visitor', 'Cdn-Loop'
]

@app.route('/proxy/<path:url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(url):
    # 解码并清理URL
    target_url = unquote(url).strip()
    
    # 自动补全协议头
    if not target_url.startswith(('http://', 'https://')):
        if re.match(r'^[a-zA-Z0-9]', target_url):  # 如果以字母或数字开头
            target_url = f'https://{target_url}'
        else:
            abort(400, description="Invalid URL format")
    
    # 严格验证URL格式
    try:
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError
    except ValueError:
        abort(400, description="Invalid URL structure")

    try:
        # 构造转发请求头（增强过滤）
        headers = {
            key: value for key, value in request.headers
            if key.lower() not in {
                'host', 'cookie', 'authorization', 
                'cf-connecting-ip', 'cf-ipcountry', 'cf-ray',
                'cf-visitor', 'cdn-loop'
            } | {h.lower() for h in SENSITIVE_HEADERS}
        }
        headers['Accept-Encoding'] = 'identity'  # 禁用压缩编码

        # 转发请求（禁用自动解压）
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            stream=True,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=True
        )

        # 构造响应
        excluded_headers = [
            'content-encoding', 'content-length', 
            'transfer-encoding', 'connection'
        ] + SENSITIVE_HEADERS

        response = Response(
            resp.iter_content(chunk_size=8192),
            status=resp.status_code,
            headers={
                k: v for k, v in resp.headers.items()
                if k.lower() not in [h.lower() for h in excluded_headers]
            }
        )

        # 处理重定向（保持代理链）
        if 300 <= resp.status_code < 400:
            location = resp.headers.get('Location')
            if location:
                if location.startswith(('http://', 'https://')):
                    new_location = f'/proxy/{location}'
                else:
                    new_location = f'/proxy/{parsed.scheme}://{parsed.netloc}{location}'
                response.headers['Location'] = new_location

        # 强制设置内容类型
        if 'Content-Type' not in response.headers:
            response.headers['Content-Type'] = resp.headers.get('Content-Type', 'application/octet-stream')

        return response

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Proxy error: {str(e)}")
        abort(502, description="Bad gateway")

# 拦截根路径的非法请求
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def block_root_access(path):
    abort(403, description="Direct root access not allowed")

@app.route('/healthz')
def health_check():
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3469)