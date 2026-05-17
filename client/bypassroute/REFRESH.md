# Refresh embedded RU CIDR snapshot

Source: RIPE delegated extended stats
URL: https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest

## Procedure

```bash
cd shadowlink
go run ./tools/cidr-snapshot \
    --source https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest \
    --country RU \
    --out-blob client/bypassroute/embedded_ru.bin \
    --out-go client/bypassroute/embedded.go
go test ./client/bypassroute/...
```

## Cadence

Recommend monthly regen; attach to Friday release cut.
