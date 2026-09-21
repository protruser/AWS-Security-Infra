#!/bin/bash
# lambda_b 배포 패키지를 만든다. terraform plan/apply 전에 먼저 실행한다.
# Lambda 런타임(python3.12, x86_64)에 맞춰 의존성을 build/ 에 설치하고, 공통 DB 코드(lambda_common)를 함께 넣는다.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf build
mkdir build
pip install --quiet --target build --platform manylinux2014_x86_64 \
  --python-version 3.12 --only-binary=:all: --implementation cp -r requirements.txt
cp lambda_b.py waf.py build/
cp -r ../../lambda_common/common build/common
find build -name '__pycache__' -type d -prune -exec rm -rf {} +
echo "built: $(pwd)/build"
