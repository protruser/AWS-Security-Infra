#!/bin/bash
# terraform plan 파일에서 "어떤 리소스를 어떻게 바꾸는지"만 뽑는다.
# 레포가 public 이라 로그/PR 코멘트에 값(IP, ARN, 설정값)을 남기지 않기 위해
# 리소스 주소와 동작(create/update/delete)만 출력한다. 주소는 코드에서 나오는 이름이다.
#
# 사용법: plan-summary.sh <planfile>
# 출력: 한 줄에 "<동작> <리소스 주소>" (정렬됨). 변경이 없으면 빈 출력.
set -euo pipefail

terraform show -json "$1" | jq -r '
  .resource_changes[]?
  | select(.change.actions != ["no-op"] and .change.actions != ["read"])
  | "\(.change.actions | join("+")) \(.address)"
' | sort
