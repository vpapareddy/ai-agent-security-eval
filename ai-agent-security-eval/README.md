# AI Agent Security Evaluation

`AI Agent Security Evaluation` is a local-first FastAPI service that simulates an enterprise internal copilot and exposes concrete agent safety, policy, tracing, and adversarial evaluation controls.

The deployment story is intentionally simple:

- local-first Python + FastAPI + SQLite
- one application container
- plain Kubernetes manifests
- internal-only service
- scheduled evals via CronJob
- env-driven configuration
- standard-library logging only

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

## Configuration

The app uses local defaults so it can run immediately, but runtime settings are externalized through env vars.

Required for normal local use:

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
- `OPTIONAL_LLM_API_KEY` optional example secret for a future adapter

`APP_AUTO_SEED=true` is useful in Docker or Kubernetes because it bootstraps demo data when storage is empty without wiping existing data on every restart.

## Local Run

Setup:

```bash
cd /Users/vikrant/Desktop/ai-agent-security-eval
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m scripts.seed_data
```

Start the API:

```bash
source .venv/bin/activate
python -m scripts.run_server
```

Run tests:

```bash
source .venv/bin/activate
pytest -q
```

Run local adversarial evals:

```bash
source .venv/bin/activate
python -m scripts.run_evals
```

## Docker

Build:

```bash
cd /Users/vikrant/Desktop/ai-agent-security-eval
docker build -t ai-agent-security-eval:local .
```

Run:

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

The image uses `python -m scripts.run_server` as the default startup command and logs directly to stdout.

## Kubernetes

The manifests live in `/k8s`:

- `configmap.yaml`: non-secret runtime configuration
- `deployment.yaml`: runs the FastAPI API
- `service.yaml`: exposes the API internally as a `ClusterIP` service
- `cronjob-evals.yaml`: runs scheduled adversarial evaluations
- `secret.example.yaml`: example secret for optional API keys or future adapters
- `networkpolicy.yaml`: restricts ingress to app pods and keeps egress narrow

Build and load the image:

For `kind`:

```bash
docker build -t ai-agent-security-eval:local .
kind load docker-image ai-agent-security-eval:local
```

For `minikube`:

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

Optional secret example:

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
kubectl logs cronjob/ai-agent-security-eval-evals
kubectl logs job/manual-evals
```

Inspect the deployment:

```bash
kubectl get deploy,svc,cronjob,pods
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

Restricted data block:

```bash
curl -X POST http://127.0.0.1:8000/run-task \
  -H "Content-Type: application/json" \
  -d '{"task":"Query the customer SSN details for jamie.lee@acme.test"}'
```

Inspect a run:

```bash
curl http://127.0.0.1:8000/runs/1
```

Inspect findings:

```bash
curl http://127.0.0.1:8000/findings
```

## How To Inspect Results

Local files:

- SQLite database: `data/app.db`
- local eval report: `data/eval_report.json`
- seeded docs: `data/docs/`

Useful checks:

- `GET /runs/{id}` for a full run trace
- `GET /findings` for blocked tool calls and eval failures
- container logs for startup, request handling, tool use, policy decisions, and eval execution

## Notes

- The deployment is intentionally interview-friendly: one app container, one service, one CronJob, one ConfigMap, one example Secret, one NetworkPolicy.
- The Kubernetes manifests use `emptyDir` for demo simplicity. If you want durable shared state across pod restarts or between the API and eval jobs, replace that with a `PersistentVolumeClaim`.
- There is still no auth system; `user_role` remains simulated input for local security testing.
- The SQL policy parser is intentionally narrow and optimized for this demo's allowed query shapes.
