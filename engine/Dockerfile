# build-base is not optional decoration. The Target crawler parses JavaScript
# with github.com/BishopFox/jsluice, which parses through
# github.com/smacker/go-tree-sitter, and tree-sitter is C. The default
# golang:alpine image ships no C compiler, so a build without build-base fails
# with an "invalid argument" or a missing-header error inside cgo rather than
# with anything that names the real cause.
#
# The toolchain is installed in the build stage only. The runtime stage below
# copies /engine and /httpx across and never sees a compiler.

# Ланцюг дзеркал для завантаження Go-модулів з engine/go.mod.
#
# Ланцюг такий самий, як `GOPROXY_MIRRORS` у `start.sh`, щоб контейнер і
# нативний стенд завантажували однаково. GOSUMDB не змінюється:
# `sum.golang.org` відповідає 200, тобто перевірка контрольних сум з engine/go.sum
# активна, і `GOSUMDB=off` послабив би ланцюг постачання без потреби.
ARG GOPROXY_CHAIN="https://proxy.golang.org,direct https://goproxy.cn,direct https://proxy.golang.com.cn,direct"
ARG GOPROXY_ATTEMPTS=3

FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
ARG GOPROXY_CHAIN
ARG GOPROXY_ATTEMPTS
RUN apk add --no-cache build-base
WORKDIR /src
COPY . .
# Контейнер збирається виключно із залежностей актуального проєкту (engine/go.mod та engine/go.sum).
# Спочатку виконується `go mod download` через ланцюг дзеркал, після чого і `/engine`,
# і `/httpx` (`github.com/projectdiscovery/httpx/cmd/httpx`, зафіксований у `engine/go.mod`)
# компілюються детерміновано без додаткових мережевих запитів і без захардкоджених версій.
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    set -eu; \
    fetched=0; \
    for mirror in ${GOPROXY_CHAIN}; do \
      for attempt in $(seq 1 ${GOPROXY_ATTEMPTS}); do \
        echo "--- модулі з engine/go.mod через ${mirror}, спроба ${attempt}/${GOPROXY_ATTEMPTS}"; \
        if GOPROXY="${mirror}" go mod download; then fetched=1; break 2; fi; \
      done; \
    done; \
    if [ "${fetched}" != "1" ]; then \
      echo "жодне дзеркало GOPROXY не спрацювало за ${GOPROXY_ATTEMPTS} спроб: ${GOPROXY_CHAIN}" >&2; \
      echo "це мережева помилка завантаження модулів, а не помилка збірки" >&2; \
      exit 1; \
    fi; \
    echo "--- збірка /engine та /httpx із залежностей engine/go.mod без мережі"; \
    CGO_ENABLED=1 go build -o /engine . ; \
    CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /httpx github.com/projectdiscovery/httpx/cmd/httpx

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
COPY --from=build /engine /engine
COPY --from=build /httpx /usr/local/bin/httpx
RUN apk add --no-cache ca-certificates
EXPOSE 8080 8081
ENTRYPOINT ["/engine"]
