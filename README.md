Sateh Dynamic DNS
_Stefan Arentz, July 2023_

Ever since I switched to Bell Fibe, I seem to be frequently getting a new public IP assigned, which is a bit annoying.

This program is a small web server that you can run on a VM somewhere and it will take care of keeping a DNS record in a Cloudflare hosted zone up-to-date. It does this by taking the IP address of the _caller_. So you run the server somewhere on the Internet and then call it from your home network.

On the server side, run it behind TLS. It doesn't have any state or database and it is configured with the following environment variables:

* `BIND_PORT` - The address to bind to (defaults to `0.0.0.0`)
* `BIND_ADDRESS` - The port to bind to (defaults to `8080`)
* `CLOUDFLARE_API_TOKEN` - The Cloudflare API token
* `ZONE_NAME` - The name of the zone, eg `example.com`
* `RECORD_NAME` - The name of the record, eg `home` or `myserver.home`
* `ACCESS_TOKEN` - Your secret token that protects this API

Keep the tokens safe. Ideally you put them in the Secrets Manager or Vault that your application hosting provider has. Specially keep the Cloudflare token secret because it is not possible to scope Clouddlare tokens to a single DNS record - it can be used to manage the whole zone.

On the client (home) side, create a cron job that calls the endpoint periodically. For example with `curl`:

```
curl -XPOST -H "Authorization: Bearer s3cr3t" https://dyndns.example.com/update
```

Either call it directly from a `crontab` or wrap it in a little shell script. You can run it every couple of minutes or even more frequent. If your IP has not changed then no API calls to Cloudflare are being made so most request will be very fast.
