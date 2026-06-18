# ds_updater

`ds_updater` checks the CDS and DS DNS records for a domain and reconciles them with a registrar API.

## How it works

- If all CDS records have a matching DS record and vice versa, the program exits without taking any action.
- If a CDS record is present with no matching DS record, an HTTP POST is sent to the configured API URL so the DS record can be created at the parent zone.
- If a DS record is present with no matching CDS record, the discrepancy is logged as a warning. No automatic deletion is performed unless `DELETE_DS=true` is set, because removing a DS record without a clear signal from the child zone would break DNSSEC.

## Configuration

All configuration is provided through environment variables.

| Variable    | Required | Default      | Description |
|-------------|----------|--------------|-------------|
| `DOMAIN`    | yes      |              | Domain name to check, e.g. `example.com` |
| `RESOLVER`  | no       | `8.8.8.8:53` | DNS resolver address |
| `API_URL`   | no       |              | URL to POST when a CDS record has no matching DS record |
| `API_KEY`   | no       |              | API key sent in the POST body |
| `API_SECRET`| no       |              | API secret sent in the POST body |
| `DELETE_DS` | no       | `false`      | Set to `true` to DELETE DS records that have no matching CDS record |

When `DELETE_DS=true`, the delete URL is derived from `API_URL` by replacing the action segment with `deleteDnssecRecord` and appending `/{domain}/{keyTag}`.

## Building

```sh
go build -o ds_updater .
```

## Running

```sh
export DELETE_DS=true
export API_URL="https://api.porkbun.com/api/json/v3/addDnssecRecord/"
export DOMAIN=example.com 

API_KEY=mykey API_SECRET=mysecret ./ds_updater
```

## Testing

```sh
go test ./...
```

## License

This program is free software: you can redistribute it and/or modify it under the terms of the [GNU General Public License](LICENSE) as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
