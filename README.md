# index-back

Web index backend

## Usage

Docker compose

```yaml
index-back:
  container_name: index-back
  build:
    context: ../index-back
    target: [production/development]
  environment:
    - DB_USER=
    - DB_PASSWORD=
    - DB_DATABASE=web
    - COOKIE_DOMAIN=
    - RECAPTCHA_SECRET=
  depends_on:
    - mariadb
  expose:
    - "80"
  volumes:
    - ../index-back:/app
    - ../.hmac:/.hmac
  networks:
    - back
```
