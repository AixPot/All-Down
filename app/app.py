from flask import Flask, request, Response, abort
import requests
from urllib.parse import unquote
import re

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 2048  # 限制2048MB请求体
TIMEOUT = 300  # 请求超时时间

# 需要删除的敏感headers
SENSITIVE_HEADERS = [
    'X-Forwarded-For', 'CF-Connecting-IP',
    'CF-IPCountry', 'CF-Ray', 'CF-Request-ID'
]

@app.route('/proxy/<path:url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
@app.route('/<path:url>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def proxy(url):
    # 自动识别两种URL格式
    if url.startswith('https:/') and not url.startswith('https://'):
        url = url.replace('https:/', 'https://', 1)
    elif url.startswith('http:/') and not url.startswith('http://'):
        url = url.replace('http:/', 'http://', 1)
    
    # 解码URL
    target_url = unquote(url)
    
    # 验证URL格式
    if not re.match(r'^https?://', target_url, re.IGNORECASE):
        abort(400, description="Invalid URL scheme")
    
    try:
        # 构造转发请求
        headers = {
            key: value for key, value in request.headers
            if key.lower() not in ['host', 'cookie', 'authorization'] + [h.lower() for h in SENSITIVE_HEADERS]
        }
        
        # 转发请求
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            stream=True,
            timeout=TIMEOUT,
            allow_redirects=False  # 手动处理重定向以保持代理链
        )

        # 构造响应
        response = Response(resp.iter_content(chunk_size=8192), status=resp.status_code)
        
        # 复制响应头（过滤敏感信息）
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response.headers.extend({
            k: v for k, v in resp.headers.items()
            if k.lower() not in excluded_headers + [h.lower() for h in SENSITIVE_HEADERS]
        })

        # 处理重定向
        if 300 <= resp.status_code < 400:
            location = resp.headers.get('Location')
            if location:
                if location.startswith(('http://', 'https://')):
                    return Response(status=resp.status_code, headers={'Location': f'/proxy/{location}'})
                else:
                    return Response(status=resp.status_code, headers={'Location': location})

        # 处理断点续传
        range_header = request.headers.get('Range')
        if range_header and resp.status_code == 206:
            response.headers['Content-Range'] = resp.headers.get('Content-Range', '')
            response.headers['Accept-Ranges'] = 'bytes'

        return response

    except requests.exceptions.RequestException as e:
        app.logger.error(f"Proxy error: {str(e)}")
        abort(502, description="Bad gateway")

@app.route('/healthz')
def health_check():
    return 'OK', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3469)
