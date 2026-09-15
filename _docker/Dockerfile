ARG FFMPEG_IMAGE=gtstef/ffmpeg:8.1-decode
ARG GO_IMAGE=golang:alpine
ARG NODE_IMAGE=node:jod-slim
ARG RUNTIME_IMAGE=alpine:latest
FROM ${FFMPEG_IMAGE} AS ffmpeg
FROM ${GO_IMAGE} AS base
ARG VERSION
ARG REVISION
WORKDIR /app
COPY ./backend ./
RUN apk update && apk add --no-cache gcc musl-dev
ENV CGO_ENABLED=1
RUN go build -mod=readonly -tags mupdf,musl -ldflags="-w -s \
  -X 'github.com/gtsteffaniak/filebrowser/backend/common/version.Version=${VERSION}' \
  -X 'github.com/gtsteffaniak/filebrowser/backend/common/version.CommitSHA=${REVISION}'" \
  -o filebrowser .
RUN mkdir /build-inputs && go list -mod=readonly -m all > /build-inputs/go-modules.txt \
    && go version > /build-inputs/go-version.txt \
    && apk info -vv > /build-inputs/go-system-packages.txt

FROM ${NODE_IMAGE} AS nbuild
WORKDIR /app
COPY ./frontend/package.json ./frontend/package-lock.json ./
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && git config --global url."https://github.com/".insteadOf "git@github.com:" \
    && git config --global url."https://github.com/".insteadOf "ssh://git@github.com/"
RUN npm ci --maxsockets 1 --no-audit --no-fund
COPY  ./frontend/ ./
RUN npm run build:docker
RUN mkdir /build-inputs && cp package-lock.json /build-inputs/frontend-package-lock.json \
    && node --version > /build-inputs/node-version.txt \
    && npm --version > /build-inputs/npm-version.txt \
    && dpkg-query -W > /build-inputs/frontend-system-packages.txt

FROM ${RUNTIME_IMAGE}
ARG VERSION
ARG REVISION
LABEL org.opencontainers.image.source="https://github.com/Tangbohu09527/CF_filebrowser-enterprise" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=ffmpeg [ "/ffmpeg", "/ffprobe", "/usr/local/bin/" ]
ENV FILEBROWSER_FFMPEG_PATH="/usr/local/bin/"
ENV FILEBROWSER_DATABASE="/home/filebrowser/data/database.db"
ENV FILEBROWSER_CONFIG="/home/filebrowser/data/config.yaml"
ENV PATH="$PATH:/home/filebrowser"
RUN apk --no-cache add ca-certificates mailcap tzdata curl exiftool
RUN mkdir -p /usr/share/filebrowser/build-inputs \
    && apk info -vv > /usr/share/filebrowser/build-inputs/runtime-packages.txt
COPY --from=base /build-inputs/ /usr/share/filebrowser/build-inputs/
COPY --from=nbuild /build-inputs/ /usr/share/filebrowser/build-inputs/
RUN adduser -D -s /bin/true -u 1000 filebrowser
USER filebrowser
WORKDIR /home/filebrowser
# copy config to two locations for compatibility
COPY --from=base --chown=filebrowser:1000 [ "/app/filebrowser", "./" ]
COPY --from=base --chown=filebrowser:1000 [ "/app/config.yaml", "./data/config.yaml" ]
COPY --from=base --chown=filebrowser:1000 [ "/app/config.yaml", "./" ]
COPY --from=base --chown=filebrowser:1000 [ "/app/reduce-rounded-corners.css", "./" ]
COPY --from=nbuild --chown=filebrowser:1000 [ "/app/dist/", "./http/dist/" ]
## sanity checks
RUN [ "filebrowser", "version" ]
RUN [ "ffmpeg", "-version" ]
RUN [ "ffprobe", "-version" ]
RUN [ "exiftool", "-ver" ]
# exposing default port for auto discovery.
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:80/health || exit 1
ENTRYPOINT [ "./filebrowser" ]
