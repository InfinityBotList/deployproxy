# DeployProxy

Deploy Proxy is a simple service to protect our deploys from unwanted access while also being quick enough unlike Cloudflare Access.

## Setting up secrets

Create a file called `secrets.yaml` with the following format using your discord app keys:

```yaml
client_id:
client_secret:
database_url: # Must be a postgres db
redis_url: # Must be a redis db
```

Make sure to add ``HOST/__dp/confirm`` to discord allowed redirect urls.