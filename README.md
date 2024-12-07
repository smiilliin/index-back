# index-back

Web index backend

## Usage

Docker compose

```yaml
index-back:
  image: smiilliin/index-back
  container_name: index-back
  build:
    context: ./index-back
    target: production
  environment:
    - DB_USER=smiilliin
    - DB_PASSWORD=
    - DB_DATABASE=
    - COOKIE_DOMAIN=
    - RECAPTCHA_SECRET=
  depends_on:
    - mariadb
  expose:
    - "80"
  volumes:
    - ./.hmac:/.hmac
  networks:
    - back
```
