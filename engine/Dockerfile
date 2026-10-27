# build-base is not optional decoration. The Target crawler parses JavaScript
# with github.com/BishopFox/jsluice, which parses through
# github.com/smacker/go-tree-sitter, and tree-sitter is C. The default
# golang:alpine image ships no C compiler, so a build without build-base fails
# with an "invalid argument" or a missing-header error inside cgo rather than
# with anything that names the real cause.
#
# The toolchain is installed in the build stage only. The runtime stage below
# copies /engine across and never sees a compiler.

# Ланцюг дзеркал — спільний для обох етапів.
#
# Виміряно 2026-10-01: `proxy.golang.org` віддає 403 з тілом
# `AccessDenied ... not available in your location` на zip
# `nuclei/v3@v3.11.1` (12.6 МБ), тоді як `.info` і `.mod` того самого модуля
# дають 200, а zip малих модулів — теж 200. Тобто блокування не загальне
# для проксі, воно стосується конкретного об'єкта, і який саме — заздалегідь
# невідомо. Одне дзеркало не є рішенням: воно теж може впасти, і тоді не
# збирається ані образ движка, ані тестовий стенд.
#
# Ланцюг такий самий, як `GOPROXY_MIRRORS` у `start.sh`, щоб контейнер і
# нативний стенд завантажували однаково. GOSUMDB не змінюється:
# `sum.golang.org` відповідає 200, тобто перевірка контрольних сум доступна,
# і `GOSUMDB=off` послабив би ланцюг постачання без потреби.
# Третє дзеркало додане 2026-10-03 за виміром: на цій машині кожен `.zip` з
# `proxy.golang.org` доходить до редиректа на `storage.googleapis.com` і
# повертає 403 — перевірено і для `klauspost/compress@v1.18.2`, і для
# `nuclei/v3@v3.11.1`, тобто блокується весь zip-шлях проксі, а не окремий
# модуль. `goproxy.cn` не рятує (`lookup goproxy.cn: server misbehaving`),
# `goproxy.io` теж 403, а `proxy.golang.com.cn` на ті самі об'єкти віддає 200.
# GOSUMDB не змінюється: вміст перевіряється контрольними сумами, додано
# дзеркало, а не довіру.
ARG GOPROXY_CHAIN="https://proxy.golang.org,direct https://goproxy.cn,direct https://proxy.golang.com.cn,direct"
# Повтори на кожне дзеркало, а не тільки зміна дзеркала.
#
# Виміряно 2026-10-01 на живій збірці: після 403 від proxy.golang.org друге
# дзеркало теж впало — але не з відмовою, а з
# `read ".../gaissmai/bart/@v/v0.29.0.zip": unexpected EOF`, тобто zip
# прийшов обірваним. Той самий об'єкт з тих самих двох дзеркал віддає
# HTTP 200 і 2 999 786 байт, отже це обрив, а не блокування.
#
# Go не повторює завантаження в межах одного проксі, а ланцюг без
# повтору перетворює транзиєнтний обрив на падіння образу. Три спроби
# на дзеркало — це retry, а не правило: воно нічого не обмежує, воно
# лише не дає мережевому збою виглядати як поломка збірки.
#
# Три, а не два, з окремого вимірювання: другий етап у живій збірці
# впав з `dial tcp: lookup goproxy.cn on 77.88.8.8:53: no such host`,
# тобто навіть другий дзеркало не завжди резолвиться. Go не переходить
# до `direct` після помилки мережі (тільки після 404/410), тому єдиний
# захист від такого — повтор.
#
# Обидва етапи монтують кеш модулів і кеш збірки через BuildKit. Без
# цього кожна невдала спроба знову качала б ~15 хвилин модулів з нуля,
# і збій мережі перетворювався на години марної роботи; кеш при цьому
# не змінює ні що збирається, ні яким чином.
ARG GOPROXY_ATTEMPTS=3

FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
ARG GOPROXY_CHAIN
ARG GOPROXY_ATTEMPTS
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
# CGO_ENABLED=1 is stated explicitly because the golang image sets it by default
# and a future base change must not turn a silent no-cgo build into a link error
# at runtime instead of a build error here.
#
# The step is split in two, and the split is the whole point: only the module
# download touches the network, so only the module download is retried across
# mirrors. `go build` afterwards is deterministic and runs once.
#
# Before the split, `go build` itself was run inside the mirror loop. Measured
# 2026-10-02, that turned a one-line compile error into six identical attempts
# and then into this message, which blames the network:
#
#   pkg/active/detect_sqli.go:186:16: undefined: timeProbe
#   жодне дзеркало GOPROXY не спрацювало за 3 спроб: https://proxy.golang.org,direct ...
#
# Six attempts over a broken source tree, three mirrors, and a final sentence
# naming a proxy that had nothing to do with it. Retrying is a decision about the
# network, and it must not be applied to a failure the network cannot fix.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    set -eu; \
    fetched=0; \
    for mirror in ${GOPROXY_CHAIN}; do \
      for attempt in $(seq 1 ${GOPROXY_ATTEMPTS}); do \
        echo "--- модулі через ${mirror}, спроба ${attempt}/${GOPROXY_ATTEMPTS}"; \
        if GOPROXY="${mirror}" go mod download; then fetched=1; break 2; fi; \
      done; \
    done; \
    if [ "${fetched}" != "1" ]; then \
      echo "жодне дзеркало GOPROXY не спрацювало за ${GOPROXY_ATTEMPTS} спроб: ${GOPROXY_CHAIN}" >&2; \
      echo "це мережева помилка завантаження модулів, а не помилка збірки" >&2; \
      exit 1; \
    fi; \
    echo "--- збірка без мережі: помилка тут означає помилку вихідного коду"; \
    CGO_ENABLED=1 go build -o /engine .

# The Scanner runs the real nuclei binary, not a re-implementation: the engine
# resolves it through RR_NUCLEI_BINARY and falls back to PATH lookup, so a
# binary that is not in the image makes every scan fail with "executable file
# not found". The version is pinned to the same v3.11.1 that run-engine.sh
# installs, and it is built from source in the Go stage already used above so
# no extra toolchain and no package manager is needed. Nuclei is Go, so the
# resulting binary is static and runs on the bare alpine runtime.
FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS nuclei
ARG NUCLEI_VERSION=v3.11.1
# Значення береться з глобального ARG вище. Другий `ARG` з default-ом тут
# був би дублем правила у двох місцях: поміняли ланцюг в одному — другий
# лишився старий, і падіння виглядало б незрозумілим.
ARG GOPROXY_CHAIN
ARG GOPROXY_ATTEMPTS
# Ланцюг такий самий, що й на етапі `build`: обидва тягнуть
# `github.com/projectdiscovery/nuclei/v3` і без ланцюга падають на тому ж
# 403 від proxy.golang.org. Пояснення вимірювання — біля глобального ARG.
# Той самий розподіл, що й на етапі `build`: у ланцюг дзеркал йде тільки
# завантаження модулів, а сама збірка йде один раз поза ним. Інакше помилка
# компіляції повторюється N разів і звітується як збій проксі — пояснення
# вимірювання біля кроку `build` вище.
#
# Скасований модуль тут відсутній: у цій стадії немає `WORKDIR /src`, а разом з
# ним і go.mod, тож `go mod download github.com/projectdiscovery/nuclei/v3`
# падає за 0.5с на «go.mod file not found», не торкаючись мережі. Тому завантаження
# йде через тимчасовий модуль.
#
# `GOPROXY=off` тут теж не годиться, і це теж виміряно: `go install pkg@version`
# робить запит на deprecation (чи не retracted версія) навіть тоді, коли модуль уже
# в кеші, і з вимкненим проксі він падає:
#
#   go: ...loading deprecation for github.com/projectdiscovery/nuclei/v3:
#       module lookup disabled by GOPROXY=off
#
# Тому проксі тут лишається той, що відпрацював на завантаженні, але без повторів:
# важкі завантаження вже в кеші, а єдиний запит — це перевірка deprecation. Збій на
# цьому кроці вже не повторюється і говорить саме про себе.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    set -eu; \
    scratch=/tmp/nuclei-fetch; mkdir -p "$scratch"; cd "$scratch"; \
    go mod init fetch >/dev/null 2>&1; \
    fetched=0; ok_mirror=''; \
    for mirror in ${GOPROXY_CHAIN}; do \
      for attempt in $(seq 1 ${GOPROXY_ATTEMPTS}); do \
        echo "--- модулі nuclei через ${mirror}, спроба ${attempt}/${GOPROXY_ATTEMPTS}"; \
        if GOPROXY="${mirror}" go get \
             github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} >/dev/null 2>&1; then \
          fetched=1; ok_mirror="${mirror}"; break 2; \
        fi; \
      done; \
    done; \
    if [ "${fetched}" != "1" ]; then \
      echo "жодне дзеркало GOPROXY не спрацювало за ${GOPROXY_ATTEMPTS} спроб: ${GOPROXY_CHAIN}" >&2; \
      echo "це мережева помилка завантаження модулів, а не помилка збірки" >&2; \
      exit 1; \
    fi; \
    echo "--- складання nuclei, повторів немає: збій тут — це помилка вихідного коду"; \
    GOPROXY="${ok_mirror}" GOBIN=/out go install \
        github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}

# httpx — окремий процес, який запускає `engine/osint_http_probe.go:137`.
# Без нього трансформ `http_probe` (він видимий в UI:
# `web/templates/lab/index.html:2812,4011`) не працює ніколи.
#
# Виміряно 2026-10-03: у попередньому образі httpx не було взагалі — у runtime
# копіювалися лише `/engine` і `/usr/local/bin/nuclei`. Шлях, яким руйій шукає
# httpx, ALSO б не врятував: `httpxBinary()` перевіряє `RR_HTTPX_BIN` і
# `bin/httpx` відносно cwd та виконуваного файлу, але **не PATH**. Із
# `ENTRYPOINT ["/engine"]` це дає лише `/bin/httpx`, де на alpine живе busybox
# без аплету `httpx`, — `os.Stat` не проходить, і кожен запуск відповідав
# `HTTPX_BINARY_MISSING`. Тому бінарник копіюється сюди, а compose задає
# `RR_HTTPX_BIN`.
#
# Етап побудовано як `ensure_pdtools` у `start.sh`, а не як стадію nuclei, і це
# не стилістичне: перша версія цього етапу робила `go get` у тимчасовому модулі
# (схема стадії nuclei) і падала на живій збірці — `go get` у порожньому модулі
# вирішує `github.com/klauspost/compress` інакше, ніж `go install pkg@version`,
# і тягнув версію, недоступну на першому дзеркалі:
#
#   reading https://proxy.golang.org/github.com/klauspost/compress/@v/v1.18.2.zip: 403 Forbidden
#
# Тоді як `go install github.com/projectdiscovery/httpx/cmd/httpx@v1.11.0` —
# рівно та команда, яку виконує `ensure_pdtools` — проходить на тій самій машині
# з першого дзеркала. Тобто складність була не потрібна, а ланцюг дзеркал
# працює.
FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS httpx
ARG HTTPX_VERSION=v1.11.0
ARG GOPROXY_MIRRORS="https://proxy.golang.org,direct https://goproxy.cn,direct https://proxy.golang.com.cn,direct"
ARG GOPROXY_ATTEMPTS=3
# Повтор — це retry, а не правило: він не обмежує роботу, а лише не дає
# мережевому збою виглядати як поламка збірки. Причина та сама, що в стадії
# `build` вище.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    set -eu; \
    fetched=0; ok_mirror=''; \
    for mirror in ${GOPROXY_MIRRORS}; do \
      for attempt in $(seq 1 ${GOPROXY_ATTEMPTS}); do \
        echo "--- httpx через ${mirror}, спроба ${attempt}/${GOPROXY_ATTEMPTS}"; \
        if GOPROXY="${mirror}" GOBIN=/out go install \
             "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}"; then \
          fetched=1; ok_mirror="${mirror}"; break 2; \
        fi; \
      done; \
    done; \
    if [ "${fetched}" != "1" ]; then \
      echo "жодне дзеркало GOPROXY не спрацювало за ${GOPROXY_ATTEMPTS} спроб: ${GOPROXY_MIRRORS}" >&2; \
      echo "це мережева помилка завантаження модулів, а не помилка збірки" >&2; \
      exit 1; \
    fi

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
COPY --from=build /engine /engine
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
COPY --from=httpx /out/httpx /usr/local/bin/httpx
# nuclei dials HTTPS for its own update and library fetches, so the runtime
# needs the CA bundle. It is already present in this base image, but the
# package is stated explicitly so a future base change cannot silently drop it
# and turn every scan into a TLS failure.
RUN apk add --no-cache ca-certificates
EXPOSE 8080 8081
ENTRYPOINT ["/engine"]
