# AFR infrastructure (Terraform)

L11 §2. Modules: `network`, `rds`, `ecs-service`, `kms`. `cdn`, `observability` and `dns` come later. Environments are separate AWS accounts; only `envs/staging` exists so far (P3-12).

Nothing here runs in CI. An operator plans and applies by hand from an AWS session in the target account. Secret values never pass through Terraform: it creates empty Secrets Manager entries, and an operator fills them.

## Staging, first apply

The staging account allows only **eu-north-1** (an organisation SCP denies other regions). It's also on the AWS Free plan, which caps RDS backup retention, so `envs/staging` uses a db.t4g.micro with 1-day backups and no Performance Insights, and puts interface endpoints in 1 AZ. Pass `-var region=eu-north-1 -var api_desired_count=1`. Terraform can't read `aws login` sessions, so export them first: `eval "$(aws configure export-credentials --format env)"`.

There's no domain yet, so the HTTPS listener uses a self-signed certificate imported into ACM:
- import one for a placeholder name for the first apply;
- then re-import it under the same ARN for the ALB's DNS name (`aws acm import-certificate --certificate-arn …`);
- clients pass it as `NODE_EXTRA_CA_CERTS`.

1. **State backend.** Create the S3 bucket (versioned, encrypted) and the DynamoDB lock table once. Then:
   ```bash
   cp infra/terraform/envs/staging/backend.hcl.example infra/terraform/envs/staging/backend.hcl  # staging: bucket afr-tfstate-staging-668857951374, region eu-north-1
   terraform -chdir=infra/terraform/envs/staging init -backend-config=backend.hcl
   ```
2. **Images.** Build the anchor and api images and push them to the `afr/anchor` and `afr/api` ECR repos. Tags are immutable, so use the git sha.
   ```bash
   docker build -f infra/docker/service.Dockerfile --build-arg APP=anchor -t afr/anchor:$(git rev-parse --short HEAD) .
   ```
   ```bash
   docker build -f infra/docker/service.Dockerfile --build-arg APP=api -t afr/api:$(git rev-parse --short HEAD) .
   ```
   The repo doesn't exist until the first apply, so apply once with `-target=aws_ecr_repository.this` first, then push.
3. **Plan and apply.**
   ```bash
   terraform -chdir=infra/terraform/envs/staging plan -var certificate_arn=arn:aws:acm:… -var anchor_image_tag=<sha> -var api_image_tag=<sha> -var siwe_domain=app.staging.example -out tfplan
   terraform -chdir=infra/terraform/envs/staging apply tfplan
   ```
4. **Secrets.** Fill each `afr-staging/*` secret with `aws secretsmanager put-secret-value`. Pipe the values in from stdin (`--secret-string file:///dev/stdin`) so they never show up on screen. You need the PG URL, the Base Sepolia RPC URL, the Arkiv access key and the Arkiv writer key.
   - Build the PG URL from the RDS-managed master secret: `postgresql://afr_admin:<url-encoded password>@<rds endpoint>:5432/afr?sslmode=verify-full`.
   - The images trust the Amazon RDS CAs (`infra/docker/rds-global-bundle.pem`, via `NODE_EXTRA_CA_CERTS`), so `verify-full` works.
5. **Allowlist the KMS anchor key.** Derive its address from the public key. The key never leaves KMS.
   ```bash
   aws kms get-public-key --key-id "$(terraform -chdir=infra/terraform/envs/staging output -raw anchor_key_id)" --query PublicKey --output text | base64 -d | tail -c 64 | xxd -p -c 64
   ```
   Then derive the address: `cast keccak 0x<that hex>` and keep the last 40 hex digits.
   - The RecorderAnchor admin calls `setRecorder(<address>, true)` on `0x976cf1d60b3dc477c70b9e649005f5a12202d341` (Base Sepolia).
   - Fund the address with a little Base Sepolia ETH.
   - The service refuses to start (`NOT_RECORDER`) until the address is allowlisted.
6. **A4 check.** Once the anchor task runs, its `Anchored` events on BaseScan come from the KMS-derived address.

## What the key policy enforces

The anchor key's policy lets account admins manage the key but not sign with it, and denies `kms:Sign` to any principal other than the anchor task role. EventBridge rules publish to the `afr-staging-alerts` SNS topic on:
- a `Sign` by any other principal;
- a key-policy change, grant, disable or deletion.

These rules need CloudTrail management events in the account, for example from an organisation trail.

## Shortcuts

- **API rate limits:** no Redis yet, so each API task counts its own requests (L8 §7).
- **API migrations:** the API runs them at startup, serialised by an advisory lock. A migration that breaks the running version needs an expand/contract rollout.
- **Image architecture:** the ecs-service module defaults to ARM64. Images built on an amd64 machine without buildx need `-var cpu_architecture=X86_64`; staging runs that way today.
- **Org and recorder key:** `tools/e2e/scripts/staging-provision.ts` signs in with SIWE as a throwaway wallet and creates an org, an agent and a recorder key, as the dashboard would. `testnet-e2e.ts --api https://… --agent …` then records through the deployment and waits for its anchor service.
- **Database login:** services connect with password URLs from Secrets Manager. RDS rotates its managed master password every 7 days, and the URL secrets don't follow. Refill them after a rotation, until IAM token auth is wired in. The RDS instance has IAM auth enabled, but token auth isn't wired into the services.
- **Not modelled yet:** NAT egress allowlisting, WAF and CloudFront (`cdn`), and the `observability` module.
