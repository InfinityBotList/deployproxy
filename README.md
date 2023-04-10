# DeployProxy

Deploy Proxy is a simple service to protect our deploys from unwanted access while also being quick enough unlike Cloudflare Access.

## Setting up secrets

Create a file called `secrets.yaml` with the following format using your discord app keys:

```yaml
client_id:
client_secret:
database_url: # Must be a postgres db
redis_url: # Must be a redis db
bot_token: # Bot token of the logging/security bot
log_channel: # The channel to log to
dp_secret: # The secret to send as "X-DP-Secret" for further authentication by other services
```

For github, also set ``github_webhook_sig`` and  ``github_pat``

Make sure to add ``HOST/__dp/confirm`` to discord allowed redirect urls.