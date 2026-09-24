FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /engine .

FROM alpine:3.22
COPY --from=build /engine /engine
EXPOSE 8080 8081
ENTRYPOINT ["/engine"]
