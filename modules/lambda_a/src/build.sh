#!/bin/bash
# lambda_a 배포 패키지를 만든다. terraform plan/apply 전에 먼저 실행한다.
# Lambda 런타임(python3.12, x86_64)에 맞춰 의존성을 build/ 에 설치하고, 공통 DB 코드(lambda_common)를 함께 넣는다.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf build
mkdir build
pip install --quiet --no-compile --target build --platform manylinux2014_x86_64 \
  --python-version 3.12 --only-binary=:all: --implementation cp -r requirements.txt
cp lambda_a.py build/
cp -r ../../lambda_common/common build/common
find build -name '__pycache__' -type d -prune -exec rm -rf {} +
# pip 가 빌드한 OS 에 따라 다르게 만드는 파일(실행 파일 런처 bin/, 설치 파일 목록 RECORD)은
# Lambda 실행에 쓰이지 않으므로 지운다. 남겨두면 Windows 와 CI 의 zip 이 달라진다.
rm -rf build/bin
rm -f build/*.dist-info/RECORD
# Windows 체크아웃(CRLF)과 CI(LF)에서 zip 이 달라지지 않게 직접 작성한 코드는 LF 로 맞춘다.
perl -pi -e 's/\r$//' build/*.py build/common/*.py
echo "built: $(pwd)/build"
