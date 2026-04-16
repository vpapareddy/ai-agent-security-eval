# AI Agent Security Evaluation

`AI Agent Security Evaluation` is a local-first FastAPI service that simulates an enterprise internal copilot and demonstrates policy enforcement, tracing, and adversarial testing.

The deployment story stays intentionally simple:

- Python + FastAPI + SQLite
- one application container
- plain Kubernetes manifests
- internal-only service
- scheduled evals via CronJob
- env-driven configuration
- standard-library logging only

## What It Does

- accepts a user task through `POST /run-task`
- routes that task to one of three local tools
- enforces policy checks before tool execution
- stores runs, tool calls, drafts, and policy decisions in SQLite
- exposes traces and findings for inspection
- runs a small adversarial eval suite locally or in a CronJob

## Project Structure

```text
app/main.py
app/config.py
app/logging_config.py
agent/orchestrator.py
agent/policy.py
tools/docs_search.py
tools/sql_readonly.py
tools/draft_action.py
storage/db.py
storage/models.py
api/routes_agent.py
api/routes_system.py
scripts/seed_data.py
scripts/run_server.py
scripts/run_evals.py
k8s/
threat-model.md
```

## Requirements

- Python 3.9+
- `pip`
- Docker optional
- Kubernetes optional, such as `kind` or `minikube`

## Quick Start

Clone the repo and move into the project:

```bash
git clone https://github.com/your-user/ai-agent-security-eval.git
cd ai-agent-security-eval
```

Create a local environment and seed demo data:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m scripts.seed_data
```

Start the API:

```bash
python -m scripts.run_server
```

The API is available at [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Common Local Commands

Run tests:

```bash
source .venv/bin/activate
pytest -q
```

Run adversarial evals:

```bash
source .venv/bin/activate
python -m scripts.run_evals
```

Inspect health:

```bash
curl http://127.0.0.1:8000/health
```

## API Endpoints

- `POST /run-task`
- `GET /runs`
- `GET /runs/{id}`
- `GET /findings`
- `GET /policy`
- `GET /health`

## Example API Calls

Safe customer lookup:

```bash
curl -X POST http://127.0.0.1:8000/run-task \
  -H "Content-Type: application/json" \
  -d '{"task":"Look up the customer record for jamie.lee@acme.test"}'
```

Restricted data request that should be blocked:

```bash
curl -X POST http://127.0.0.1:8000/run-task \
  -H "Content-Type: application/json" \
  -d '{"task":"Query the customer SSN details for jamie.lee@acme.test"}'
```

Inspect a full run trace:

```bash
curl http://127.0.0.1:8000/runs/1
```

Inspect findings:

```bash
curl http://127.0.0.1:8000/findings
```

## Configuration

The app has safe local defaults, but environment-dependent settings are externalized through env vars.

Required for local use:

- none

Common env vars:

- `APP_HOST` default `127.0.0.1`
- `APP_PORT` default `8000`
- `APP_LOG_LEVEL` default `INFO`
- `APP_AGENT_NAME` default `internal_copilot`
- `APP_DEFAULT_RUN_LIMIT` default `50`
- `APP_DATA_DIR` default `./data`
- `APP_DOCS_DIR` default `./data/docs`
- `APP_DB_PATH` default `./data/app.db`
- `APP_AUTO_SEED` default `false`
- `OPTIONAL_LLM_API_KEY` optional placeholder for a future adapter

`APP_AUTO_SEED=true` is useful in Docker or Kubernetes because it seeds demo data when storage is empty without wiping existing runs on every restart.

## Docker

Build the image:

```bash
docker build -t ai-agent-security-eval:local .
```

Run the API:

```bash
docker run --rm -p 8000:8000 \
  -e APP_AUTO_SEED=true \
  -v "$(pwd)/data:/app/data" \
  ai-agent-security-eval:local
```

Run the eval harness in a container:

```bash
docker run --rm \
  -e APP_AUTO_SEED=true \
  -v "$(pwd)/data:/app/data" \
  ai-agent-security-eval:local \
  python -m scripts.run_evals
```

The image starts with `python -m scripts.run_server` and logs directly to stdout.

## Kubernetes

The manifests in `/k8s` are intentionally small and easy to explain:

- `configmap.yaml`: non-secret runtime configuration
- `deployment.yaml`: runs the FastAPI API
- `service.yaml`: exposes the API internally as a `ClusterIP` service
- `cronjob-evals.yaml`: runs scheduled adversarial evaluations
- `secret.example.yaml`: example secret for optional API keys or future adapters
- `networkpolicy.yaml`: restricts ingress to app pods and keeps egress narrow

Build and load the image for `kind`:

```bash
docker build -t ai-agent-security-eval:local .
kind load docker-image ai-agent-security-eval:local
```

Build for `minikube`:

```bash
eval $(minikube docker-env)
docker build -t ai-agent-security-eval:local .
```

Apply manifests:

```bash
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/cronjob-evals.yaml
kubectl apply -f k8s/networkpolicy.yaml
```

Apply the example secret only if you need it:

```bash
kubectl apply -f k8s/secret.example.yaml
```

Port-forward the service:

```bash
kubectl port-forward svc/ai-agent-security-eval 8000:8000
```

Trigger the scheduled eval job manually:

```bash
kubectl create job --from=cronjob/ai-agent-security-eval-evals manual-evals
```

Inspect app and eval logs:

```bash
kubectl logs deployment/ai-agent-security-eval
kubectl logs job/manual-evals
```

Inspect the deployment:

```bash
kubectl get deploy,svc,cronjob,pods
```

## How To Inspect Results

Local generated files:

- SQLite database: `data/app.db`
- eval report: `data/eval_report.json`
- seeded docs: `data/docs/`

Useful inspection paths:

- `GET /runs/{id}` for a full run trace
- `GET /findings` for blocked tool calls and eval failures
- container logs for startup, request handling, tool use, policy decisions, and eval execution

## Safe To Publish Notes

This repo is designed to be safe to publish publicly, but keep these local-only files out of GitHub:

- `.git/`
- `.venv/`
- `.env`
- `data/app.db`
- `data/eval_report.json`

If you upload files through the GitHub browser instead of `git push`, remember that `.gitignore` does not protect you. Upload only the project files you actually want in the repo.

## Notes

- The deployment is intentionally interview-friendly: one app container, one service, one CronJob, one ConfigMap, one example Secret, one NetworkPolicy.
- The Kubernetes manifests use `emptyDir` for demo simplicity. If you want durable shared state across pod restarts or between the API and eval jobs, replace that with a `PersistentVolumeClaim`.
- There is still no auth system; `user_role` remains simulated input for local security testing.
- The SQL policy parser is intentionally narrow and optimized for this demo's allowed query shapes.
