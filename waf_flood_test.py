#!/usr/bin/env python3
"""
waf_flood_test.py
------------------
본인 소유의 ALB/WAF 엔드포인트로 대량 HTTP 요청을 보내
WAF Rate-based Rule이 차단(403/429)을 시작하는지 확인하는 검증 도구.

* 반드시 본인이 소유·관리하는 리소스에만 사용하십시오.
* 상태코드 분포로 WAF 탐지 여부를 판단합니다:
    - 200 만 계속 → 아직 rate limit 미도달 (동시성/시간을 늘리세요)
    - 403 / 429 등장 → WAF가 탐지·차단 시작한 것
    실행법: pip install requests
          python waf_flood_test.py http://wonny-sec-shop-alb-718900494.ap-northeast-2.elb.amazonaws.com// -c 100 -d 30
"""

import argparse
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import requests

# ── 집계용 전역 상태 ─────────────────────────────
counter = Counter()          # 상태코드별 카운트 (예: {200: 1500, 403: 320})
errors = 0                   # 연결 실패 등 예외 카운트
lock = threading.Lock()
stop_flag = threading.Event()


def send_one(url: str, timeout: float):
    """요청 1건 전송 후 상태코드를 집계."""
    global errors
    try:
        r = requests.get(url, timeout=timeout)
        with lock:
            counter[r.status_code] += 1
    except requests.RequestException:
        with lock:
            errors += 1


def worker(url: str, timeout: float):
    """stop_flag가 설정될 때까지 계속 요청을 보내는 워커."""
    while not stop_flag.is_set():
        send_one(url, timeout)


def reporter(interval: float):
    """interval초마다 현재 상태코드 분포를 출력."""
    prev_total = 0
    while not stop_flag.is_set():
        time.sleep(interval)
        with lock:
            snapshot = dict(counter)
            total = sum(snapshot.values())
            err = errors
        rps = (total - prev_total) / interval
        prev_total = total
        blocked = snapshot.get(403, 0) + snapshot.get(429, 0)
        ok = snapshot.get(200, 0)
        block_ratio = (blocked / total * 100) if total else 0
        print(
            f"[{time.strftime('%H:%M:%S')}] "
            f"총 {total:>6} | ~{rps:5.0f} req/s | "
            f"200={ok:<6} 차단(403/429)={blocked:<6} "
            f"({block_ratio:4.1f}%) | 오류={err}"
        )


def main():
    p = argparse.ArgumentParser(description="WAF rate-limit 탐지 검증 도구")
    p.add_argument("url", help="http://wonny-sec-shop-alb-718900494.ap-northeast-2.elb.amazonaws.com/)")
    p.add_argument("-c", "--concurrency", type=int, default=50,
                   help="동시 워커 수 (기본 50)")
    p.add_argument("-d", "--duration", type=float, default=30,
                   help="지속 시간(초) (기본 30)")
    p.add_argument("-t", "--timeout", type=float, default=5,
                   help="요청 타임아웃(초) (기본 5)")
    p.add_argument("-i", "--interval", type=float, default=2,
                   help="중간 보고 주기(초) (기본 2)")
    args = p.parse_args()

    print(f"대상   : {args.url}")
    print(f"동시성 : {args.concurrency}  |  지속: {args.duration}s")
    print("-" * 60)

    rep = threading.Thread(target=reporter, args=(args.interval,), daemon=True)
    rep.start()

    start = time.time()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for _ in range(args.concurrency):
            pool.submit(worker, args.url, args.timeout)
        time.sleep(args.duration)
        stop_flag.set()

    elapsed = time.time() - start
    total = sum(counter.values())
    blocked = counter.get(403, 0) + counter.get(429, 0)

    print("-" * 60)
    print("■ 최종 결과")
    print(f"  경과 시간   : {elapsed:.1f}s")
    print(f"  총 요청     : {total}  (평균 {total/elapsed:.0f} req/s)")
    print(f"  상태코드 분포: {dict(counter)}")
    print(f"  연결 오류   : {errors}")
    print("-" * 60)
    if blocked > 0:
        print(f"✅ WAF 탐지 확인: 차단 응답(403/429) {blocked}건 발생")
    else:
        print("⚠️ 차단 응답 없음 → rate limit 미도달. "
              "-c(동시성) 또는 -d(시간)를 늘려 다시 시도하십시오.")


if __name__ == "__main__":
    main()