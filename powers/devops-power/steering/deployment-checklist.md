# Deployment Checklist

## Before deploying

- [ ] All tests pass in CI, not just locally
- [ ] Database migrations are backward-compatible with the currently deployed code (for zero-downtime deploys)
- [ ] Environment variables for the target environment are confirmed present and correct
- [ ] Rollback plan is written down, not improvised after something breaks

## Risk classification

Treat these as high-risk and require explicit human confirmation before proceeding:
- Production database migrations, especially ones dropping or renaming columns
- Infrastructure changes (scaling, networking, DNS)
- Changes to authentication or authorization configuration
- Any deploy outside normal business hours without on-call coverage

## During deployment

- [ ] Deploy to a staging/canary environment first if one exists
- [ ] Monitor error rates and latency during and immediately after rollout
- [ ] Keep the previous version's artifact/image available for immediate rollback

## After deployment

- [ ] Confirm health checks are green
- [ ] Watch error tracking (Sentry or equivalent) for a spike in the first 15-30 minutes
- [ ] Close out the deployment ticket/PR with what was deployed and when

## Rollback triggers

Roll back immediately if any of these occur post-deploy, rather than trying to hotfix forward under pressure:
- Error rate increases beyond an agreed threshold
- A health check fails and doesn't recover within a few minutes
- A data integrity issue is discovered
