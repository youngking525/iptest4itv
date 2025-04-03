#!/usr/bin/env python3
# File: iptest.py

import requests
from urllib.parse import urlparse, urlunparse
import os
import datetime
import random
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# 文件路径定义（使用相对路径）
script_dir = os.path.dirname(os.path.abspath(__file__))
ip_file_path = os.path.join(script_dir, 'ip.txt')
fail_file_path = os.path.join(script_dir, 'fail.txt')
true_file_path = os.path.join(script_dir, 'true.txt')
log_file_path = os.path.join(script_dir, 'iptest.log')
selected_ip_path = os.path.join(script_dir, '1.txt')

# 要验证的多个初始请求 URL 列表，按简化称呼分组
initial_urls = [
    ('ystenlive', 'http://gslbserv.itv.cmvideo.cn/1.m3u8?channel-id=ystenlive&Contentid=1000000005000265001&livemode=1&stbId=ass'),
    ('wasusyt', 'http://gslbserv.itv.cmvideo.cn/1.m3u8?channel-id=wasusyt&Contentid=6000000001000029752&livemode=1&stbId=ass'),
    ('bestzb', 'http://gslbserv.itv.cmvideo.cn/1.m3u8?channel-id=bestzb&Contentid=5000000004000002226&livemode=1&stbId=ass'),
    ('hnbblive', 'http://gslbserv.itv.cmvideo.cn/1.m3u8?channel-id=hnbblive&Contentid=7745129417417101820&livemode=1&stbId=ass'),
    ('FifastbLive', 'http://gslbserv.itv.cmvideo.cn/1.m3u8?channel-id=FifastbLive&Contentid=3000000020000011528&livemode=1&stbId=ass'),
]

# 创建或清空日志文件，并写入标题
log_lock = threading.Lock()

with open(log_file_path, 'w') as log_file:
    log_file.write(f"IP 验证日志 - {datetime.datetime.now()}\n")
    log_file.write("="*50 + "\n\n")

def log(message):
    """线程安全的日志记录函数。"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_message = f"[{timestamp}] {message}\n"
    with log_lock:
        try:
            with open(log_file_path, 'a') as log_file:
                log_file.write(formatted_message)
        except Exception:
            pass  # 避免日志写入失败影响主流程
    print(formatted_message, end='')

def read_fail_ips(fail_file):
    """读取失败的 IP 地址，返回集合。"""
    if os.path.exists(fail_file):
        try:
            with open(fail_file, 'r') as f:
                return set(line.strip() for line in f if line.strip())
        except Exception as e:
            log(f"❌ 读取失败的 IP 文件失败，错误: {e}\n")
            return set()
    return set()

def validate_ip(session, ip, initial_urls):
    """验证单个 IP 是否能够访问所有指定的 .m3u8 地址。"""
    # 为每个 IP 随机打乱验证顺序
    randomized_urls = initial_urls.copy()
    random.shuffle(randomized_urls)

    for label, initial_url in randomized_urls:
        log(f"验证 IP {ip} 的 {label}: ")

        try:
            response = session.get(initial_url, allow_redirects=False, timeout=3)
            if response.status_code not in (301, 302):
                log(f"初始请求返回非重定向状态码 {response.status_code}。\n")
                return False
            redirect_url = response.headers.get('Location')
            if not redirect_url:
                log(f"未找到重定向 URL。\n")
                return False
        except requests.exceptions.RequestException as e:
            log(f"初始请求失败，错误: {e}\n")
            return False

        # 解析重定向后的 URL
        parsed_redirect = urlparse(redirect_url)
        scheme = parsed_redirect.scheme
        host = parsed_redirect.hostname
        port = parsed_redirect.port or (80 if scheme == 'http' else 443)
        path = parsed_redirect.path
        query = parsed_redirect.query

        # 构建新的 URL，使用目标 IP 作为主机
        final_url = urlunparse((scheme, f"{ip}:{port}", path, '', query, ''))

        # 设置 Host 头部为原始的主机名
        headers_final = {
            'Host': host,
            'Accept': 'application/vnd.apple.mpegurl',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'Cache-Control': 'max-age=2',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Referer': 'http://gslbserv.itv.cmvideo.cn/',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0'
            )
        }

        try:
            response_final = session.get(final_url, headers=headers_final, timeout=3, verify=False)
            content_type = response_final.headers.get('Content-Type', '')
            if response_final.status_code == 200 and 'application/vnd.apple.mpegurl' in content_type:
                log("有效\n")
            else:
                log("无效\n")
                return False
        except requests.exceptions.RequestException as e:
            log(f"无效，错误: {e}\n")
            return False

    return True

def ping_ip(ip):
    """对指定 IP 进行 Ping 测试，返回平均延迟时间（毫秒）。只 Ping 两次。"""
    try:
        # 使用 subprocess 进行 Ping
        # '-c 2' 表示 Ping 两次，'-W 1' 表示超时时间为1秒
        result = subprocess.run(['ping', '-c', '2', '-W', '1', ip],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        if result.returncode == 0:
            # 解析 Ping 结果，提取平均延迟
            lines = result.stdout.splitlines()
            for line in lines:
                if 'rtt min/avg/max/mdev' in line or 'round-trip min/avg/max/stddev' in line:
                    # 支持不同系统的 Ping 输出
                    parts = line.split('=')
                    if len(parts) == 2:
                        stats = parts[1].strip().split('/')
                        if len(stats) >= 2:
                            avg_latency = float(stats[1])
                            return avg_latency
        return None
    except Exception as e:
        log(f"❌ Ping {ip} 失败，错误: {e}\n")
        return None

def append_to_file(file_path, ips):
    """将 IP 列表追加到指定文件，并去重。"""
    if not ips:
        return
    existing_ips = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        existing_ips.add(ip)
        except Exception as e:
            log(f"❌ 读取 {file_path} 失败，错误: {e}\n")
    new_ips = set(ips) - existing_ips
    if new_ips:
        try:
            with open(file_path, 'a') as f:
                for ip in new_ips:
                    f.write(f"{ip}\n")
        except Exception as e:
            log(f"❌ 写入 {file_path} 失败，错误: {e}\n")

def perform_ping_tests(valid_ips, max_ping=2):
    """对有效 IP 进行 Ping 测试，找出延迟最低的 IP。"""
    if not valid_ips:
        log("没有有效的 IP 可供 Ping 测试。\n")
        return None

    log("开始对有效 IP 进行 Ping 测试，以找出延迟最低的 IP。\n")
    lowest_latency = None
    selected_ip = None

    for idx, ip in enumerate(valid_ips, start=1):
        log(f"Ping IP {ip}: ")
        avg_latency = ping_ip(ip)
        if avg_latency is not None:
            log(f"平均延迟 {avg_latency} ms\n")
            if (lowest_latency is None) or (avg_latency < lowest_latency):
                lowest_latency = avg_latency
                selected_ip = ip
        else:
            log("Ping 失败\n")

        # 进度显示（每处理1000个IP显示一次）
        if idx % 1000 == 0:
            log(f"已完成 Ping 测试 {idx} / {len(valid_ips)} 个 IP。\n")

    if selected_ip:
        log(f"\n🎯 延迟最低的 IP 是 {selected_ip}，平均延迟 {lowest_latency} ms。\n")
        return selected_ip
    else:
        if valid_ips:
            selected_ip = random.choice(valid_ips)
            log(f"\n⚠️ 没有有效 IP 能够 Ping 通，随机选择 IP {selected_ip}。\n")
            return selected_ip
        else:
            log(f"\n⚠️ 没有有效 IP 可供 Ping 通，且没有可选择的 IP。\n")
            return None

def main():
    # 读取失败的 IP 地址
    fail_ips = read_fail_ips(fail_file_path)

    # 创建一个会话对象
    session = requests.Session()
    session.headers.update({
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0'
        ),
        'Accept': (
            'text/html,application/xhtml+xml,application/xml;q=0.9,'
            'image/avif,image/webp,image/apng,*/*;q=0.8,'
            'application/signed-exchange;v=b3;q=0.7'
        ),
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'Referer': 'http://gslbserv.itv.cmvideo.cn/',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'keep-alive'
    })
    session.verify = False  # 忽略 SSL 验证

    # 设置最大线程数
    max_threads = 2  # 设置为2线程

    log("开始验证 IP 地址...\n")

    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_ip = {}
            if os.path.exists(ip_file_path):
                with open(ip_file_path, 'r') as ip_file:
                    for line in ip_file:
                        ip = line.strip()
                        if ip and ip not in fail_ips:
                            future = executor.submit(validate_ip, session, ip, initial_urls)
                            future_to_ip[future] = ip
            else:
                log(f"❌ 未找到 IP 文件 {ip_file_path}。\n")
                sys.exit(1)

            total_ips = len(future_to_ip)
            log(f"共需验证 {total_ips} 个 IP。\n\n")

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_valid = future.result()
                    if is_valid:
                        try:
                            with open(true_file_path, 'a') as true_file:
                                true_file.write(f"{ip}\n")
                            log(f"🎉 IP {ip} 是有效的。\n\n")
                        except Exception as e:
                            log(f"❌ 写入 {true_file_path} 失败，错误: {e}\n")
                    else:
                        try:
                            with open(fail_file_path, 'a') as fail_file:
                                fail_file.write(f"{ip}\n")
                            log(f"⚠️ IP {ip} 无效。\n\n")
                        except Exception as e:
                            log(f"❌ 写入 {fail_file_path} 失败，错误: {e}\n")
                except Exception as exc:
                    log(f"⚠️ IP {ip} 生成异常: {exc}\n")
                    try:
                        with open(fail_file_path, 'a') as fail_file:
                            fail_file.write(f"{ip}\n")
                    except Exception as e:
                        log(f"❌ 写入 {fail_file_path} 失败，错误: {e}\n")

    except Exception as e:
        log(f"❌ 多线程执行失败，错误: {e}\n")
        return

    # Ping 测试
    # 从 true.txt 读取有效的 IPs
    valid_ips = []
    if os.path.exists(true_file_path):
        try:
            with open(true_file_path, 'r') as true_file:
                for line in true_file:
                    vip = line.strip()
                    if vip:
                        valid_ips.append(vip)
        except Exception as e:
            log(f"❌ 读取 {true_file_path} 失败，错误: {e}\n")

    # 如果有有效的 IP，进行 Ping 测试
    if valid_ips:
        selected_ip = perform_ping_tests(valid_ips, max_ping=2)
        if selected_ip:
            try:
                with open(selected_ip_path, 'w') as sel_ip_file:
                    sel_ip_file.write(f"{selected_ip}\n")
                log(f"选中的 IP 已写入 {selected_ip_path}\n")
            except Exception as e:
                log(f"❌ 写入 {selected_ip_path} 失败，错误: {e}\n")
    else:
        log("没有有效的 IP 可供 Ping 测试。\n")

    # 输出所有有效的 IP 地址
    log("\n验证完成。有效的 IP 地址如下：\n")
    for vip in valid_ips:
        log(f"- {vip}\n")
    log("")
    
if __name__ == "__main__":
    main()
