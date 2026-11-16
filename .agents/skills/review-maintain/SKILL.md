---
name: review-maintain
description: Use when a project using this guide prepares its first deployment, adds authentication or migrations, has an incident or review false positive, or changes review models or execution modes.
---

# 프로젝트 리뷰 체계 점검

프로젝트의 `REVIEW.md`, `.review/config.json`, `.review/layers.json`, `.review/manifest.json`을 읽는다. 원본 guide의 최신 버전으로 프로젝트 기준을 대체하지 않는다.

| 사건 | 확인할 자료와 변경안 |
| --- | --- |
| 첫 배포 준비 | 6·7계층의 적용 조건, 통합·기능 끄기·복구·감지의 실행 증거 |
| 인증·마이그레이션 도입 | 민감 경로, 권한·데이터 불변 조건, 회귀 테스트 |
| 버그·오탐·사고 | 해당 PR의 입력 SHA, 실행 조건, 최종 지적, 수정·검사 결과와 사람의 판단 |
| 모델·실행 경로 변경 | 승인된 문제집, 고정 rubric, 동일 입력의 기존/후보 실행 결과 |

반복 오류는 실행 가능한 테스트·린트로, 맥락 판단은 리뷰 기준으로, 누락·오탐은 평가 후보로 제안한다. 자동 수정 성공이나 닫힌 댓글은 정답 승인이 아니다. 정책·정답 확정은 모델 worker와 분리된 운영자 경로를 사용한다.

모델 비교는 시작 전에 corpus/rules/rubric hash와 `(case, configuration, trial)` 기대 목록을 고정한다. 중요 사례는 기본 3회다. 성공한 결과만 골라 비교하지 않는다. 결과 누락·중복·미상 trial·판정 보류는 비교 전체 `hold`이며 분모는 기대 목록 그대로다. 누락된 trial을 다시 실행할 때도 기존 실행을 숨기지 않고 같은 조건의 시도로 기록한다. 평균이 좋아져도 기존의 중요 발견을 놓치면 교체를 보류한다. 최종 전환은 사람이 결과를 확인해 결정한다.

평가 worker에는 input만 제공한다. 정답·수정본·judge 자료·다른 run 자료와 원본 PR 회수 경로는 worker 밖에 둔다. 실제 모델 도구의 접근 차단 증거가 없으면 평가 품질을 검증됐다고 표시하지 않는다.

결과는 **계층별 현재 상태와 증거 → 근거가 있는 변경안 → 사람 확인이 필요한 정책/정답 → 다음 재점검 조건**으로 남긴다. 기존 규칙을 보존하며 변경은 검토 가능한 diff로 제시한다. 권한·사용 한도·인증 실패에서 다른 실행 방식으로 자동 전환하지 않는다.
