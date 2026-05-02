# Deploy SQLite-Based Code (Technical Debt #1)

## Background
The deployed servers use `roots.json` / `trees.json` for Merkle data.
The repo uses SQLite (`app/var/signedby.db`).

This runbook deploys the repo code, migrating to SQLite.

## Pre-Flight Check (Run on Primary: 134.199.198.192)

```bash
# SSH to primary
ssh root@134.199.198.192

# Check if there's real data worth migrating
cat /opt/sbm-api/roots.json 2>/dev/null | python3 -m json.tool | head -50
cat /opt/sbm-api/trees.json 2>/dev/null | python3 -m json.tool | head -50

# Check current enrollment count
wc -l /opt/sbm-api/enrollments.json 2>/dev/null || echo "no enrollments file"
```

**Decision point:**
- If files are empty/minimal/test data → proceed with clean deploy (skip migration)
- If files have production data → STOP and write migration script first

## Deploy (Clean Install)

From your machine with SSH access (laptop or server):

```bash
cd ~/SignedByMe  # or wherever you cloned the repo

# Deploy to primary
./scripts/deploy.sh
```

The script will:
1. rsync `app/` to `/opt/sbm-api/app/`
2. rsync `site/` to `/opt/sbm-api/site/`
3. Install missing pip deps
4. Restart `sbm-api` service
5. Smoke test endpoints

## Post-Deploy Verification

```bash
# Check health
curl https://api.signedbyme.com/healthz

# Check OIDC discovery
curl https://api.signedbyme.com/.well-known/openid-configuration | jq .

# Check database was created
ssh root@134.199.198.192 "ls -la /opt/sbm-api/app/var/"

# Check logs for errors
ssh root@134.199.198.192 "journalctl -u sbm-api -n 50"
```

## Sync to Secondary

After primary is verified working:

```bash
# From your machine
rsync -avz --delete \
  root@134.199.198.192:/opt/sbm-api/app/ \
  root@164.90.137.161:/opt/sbm-api/app/

rsync -avz --delete \
  root@134.199.198.192:/opt/sbm-api/site/ \
  root@164.90.137.161:/opt/sbm-api/site/

# Restart secondary
ssh root@164.90.137.161 "systemctl restart sbm-api"

# Verify
curl -s https://api.signedbyme.com/healthz  # LB routes to both
```

## Clean Up Old Files (After Verification)

```bash
# On both servers
ssh root@134.199.198.192 "rm -f /opt/sbm-api/roots.json /opt/sbm-api/trees.json /opt/sbm-api/enrollments.json /opt/sbm-api/enrollment_tokens.json"

ssh root@164.90.137.161 "rm -f /opt/sbm-api/roots.json /opt/sbm-api/trees.json /opt/sbm-api/enrollments.json /opt/sbm-api/enrollment_tokens.json"
```

## Rollback (If Needed)

The old code is still in git history. To rollback:

```bash
# Find the pre-SQLite commit
git log --oneline -20

# Reset and redeploy
git checkout <old-commit>
./scripts/deploy.sh
```

---

**Note:** This deploys to PRIMARY only. Litestream will NOT replicate the new SQLite DB until Technical Debt #2 is fixed (Litestream pointing to wrong file).

After this deploy, fix #2 immediately to ensure HA replication works.
