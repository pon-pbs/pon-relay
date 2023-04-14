# PON Relay Docker services

PON Requires multiple services which needs to be run as docker for the usability.
Different Services Have been provided as docker-compose files which can be run using docker-compose

## Relay Services

Reay needs Database and Redis to run properly. This can be either started using-

```
docker run -d -p 5432:5432 -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=postgres postgres
docker run -d -p 6379:6379 redis
```
Environment Variables-

* `POSTGRES_USER` - Postgres User
* `POSTGRES_PASSWORD` - Postgres Password
* `POSTGRES_DB` - Postgres Database

You need to setup these peoperly as these will be used to run Housekeeper and Relay/

You can also use Docker Compose with `docker-core.yml` file. Run using `sudo docker-compose -f docker-core.yml up` which will setup for you-
* Postgres Server `db` On Port 5432
* Redis Server `redis` On Port 6379
* Adminer `adminer` On Port 8093 which can be used to see the Postgres Server

The servers can be stopped using `sudo docker-compose -f docker-core.yml down`

## Metabase Service
Metabase Service can be setup using docker compose and `docker-metabase.yml` file. Run using `sudo docker-compose -f docker-core.yml up` which will setup for you-
* Postgres Server `db-metabase` On Port 5431 that is used by Metabase Server
* Metabase Server `metabase` On Port 1000
The servers can be stopped using `sudo docker-compose -f docker-metabase.yml down`

You can also specify user and password for Metabase DB using variables `METABASE_DB_USER` and `METABASE_DB_PASSWORD` (Default is admin and postgres)

You can use Metabase service on `http://localhost:1000`

## RPBS Service
RPBS Service is needed for relay. You can run it on your own using-
```
sudo docker pull blockswap/rpbs-service
sudo docker run blockswap/rpbs-service
```
 Or you can run using docker-compose and `docker-rpbs.yml` file. You can run using `sudo docker-compose -f docker-rpbs.yml up` which will setup for you-

 * RPBS Service `blockswap-rpbs` on Port 3000

 The servers can be stopped using `sudo docker-compose -f docker-rpbs.yml down`

