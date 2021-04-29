@echo off
set base=%~d0%~p0

docker-compose -f %base%keycloak\docker-compose.yml down
