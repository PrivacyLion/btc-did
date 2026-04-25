# SignedByMe HA Failover Procedures

## Architecture

```
                    DO Global Load Balancer
                    api.beta.privacy-lion.com
                            |
              +-------------+-------------+
              |                           |
        Primary (ATL1)             Secondary (NYC3)
        134.199.198.192            164.90.137.161
              |                           |
              v                           v
         Litestream                  Cron restore
         (replicates)                (every 5 min)
              |                           |
              +-------------+-------------+
                            |
                     DO Spaces (NYC3)
                     signedby-backups
```

## Automatic Failover (via Load Balancer)

**Trigger:** Primary fails health check (3 consecutive failures on `/.well-known/openid-configuration`)

**What happens:**
1. LB marks primary as "Down"
2. LB routes 100% of traffic to secondary
3. Users experience zero downtime (requests in-flight may retry)
4. Uptime Kuma alerts via ntfy

**Recovery:**
1. Fix primary server
2. Restart `sbm-api` service: `systemctl restart sbm-api`
3. Wait for health check to pass (5 consecutive successes)
4. LB automatically re-adds primary to rotation

## Manual Failover (Planned Maintenance)

**Before maintenance:**
```bash
# On primary (134.199.198.192)
systemctl stop sbm-api
```

LB will detect failure and route to secondary within 30 seconds.

**After maintenance:**
```bash
# On primary
systemctl start sbm-api
```

LB will restore primary to rotation within 60 seconds.

## Database Sync

**Primary → Spaces:** Continuous via Litestream (sub-second)

**Spaces → Secondary:** Every 5 minutes via cron:
```
*/5 * * * * /usr/bin/litestream restore -config /etc/litestream.yml -if-replica-newer /opt/sbm-api/sbm.db
```

**Maximum data loss on failover:** Up to 5 minutes of writes (enrollments, login verifications)

## Promoting Secondary to Primary

If primary is permanently lost:

1. **Stop cron restore on secondary:**
   ```bash
   crontab -e
   # Comment out or delete the litestream restore line
   ```

2. **Enable Litestream replication on secondary:**
   ```bash
   systemctl enable litestream
   systemctl start litestream
   ```

3. **Update Litestream config** to use a new path (avoid conflicts):
   ```yaml
   # /etc/litestream.yml on secondary
   path: secondary/sbm.db  # Changed from primary/sbm.db
   ```

4. **Provision new secondary** (optional, for continued HA)

## Emergency Contacts

- **DigitalOcean Status:** https://status.digitalocean.com
- **DNS (GoDaddy):** https://dcc.godaddy.com
- **Uptime Kuma:** [your kuma URL]

## Verification Checklist

After any failover:

- [ ] `curl https://api.beta.privacy-lion.com/.well-known/openid-configuration` returns 200
- [ ] Both servers show "Active" in DO Load Balancer console
- [ ] Uptime Kuma shows all monitors green
- [ ] Test enrollment or login flow end-to-end
