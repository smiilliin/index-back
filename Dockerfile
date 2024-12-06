FROM golang:1.23-alpine AS development

ARG db_user
ARG db_password
ENV DB_USER=${db_user} \
    DB_PASSWORD=${db_password}
WORKDIR /app

RUN go install github.com/air-verse/air@latest

EXPOSE 80
CMD [ "air", "-c", ".air.toml" ]

FROM golang:1.23-alpine AS production

ARG db_user
ARG db_password
ENV DB_USER=${db_user} \
    DB_PASSWORD=${db_password}
WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN go build -o main .

EXPOSE 80
CMD ["./main"]