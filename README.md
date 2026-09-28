# PUC2 (CYNET) — Sub Case 2d: CACAO Playbook Authoring Training (Malicious IP Block)

A **CyberRangeCZ Sandbox Definition** that implements the full UML sequence for
*Sub Case 2d*: a trainee authors a **CACAO 2.0** playbook to block a malicious
source IP, **NG-SOAR** (KMS + CACAO Validator/Executor) stores and validates
it, the **NG-SOAR Operator** executes it (host firewall rule on the **Lab Target
Service**), and the cyber range compiles the results for **Evaluation/Reporting**.

Only the software components of the UML diagram are deployed. From the reference
`integrations` sandbox only NG-SOAR is reused; MISP, DFIR-IRIS, RITA, Portainer,
Caldera, OpenVAS, NG-SIEM, SACTI, the MCP servers and AnythingLLM are
deliberately **not** deployed. `lab-router` (Internet egress) and command logging
are CyberRangeCZ platform infrastructure, not scenario tools.

Infrastructure conventions (images, flavors, `mgmt_user`, Docker/NG-SOAR
deployment, command logging, secrets) are aligned with the real NG-SOC sandbox:
<https://github.com/NG-SOC-eu/ng-soc-ansible/tree/integrations>.

## Repository layout

```
.
├── topology.yml                      # Topology Definition (MUST be at root)
├── README.md
├── VALIDATION.md                     # Validation report
└── provisioning/
    ├── playbook.yml                  # Orchestrates roles (hostname targeting)
    ├── requirements.yml              # sandbox-logging role (installed by the platform)
    ├── requirements-collections.yml  # collections, local runs only
    ├── group_vars/all/
    │   ├── main.yml                  # Shared scenario facts (non-secret)
    │   └── vault.yml                 # Secrets (encrypt with ansible-vault)
    └── roles/
        ├── common/                   # base packages, scenario markers
        ├── docker_server/            # Docker + NG-SOAR stack (integrations pattern)
        ├── ng_soar/                  # KMS + CACAO Validator/Executor + soar-operator console
        ├── lab_target/               # protected HTTP/SSH service + nftables input (enforcement)
        ├── attacker/                 # suspicious-traffic generator (test IP)
        ├── student_ws/               # Cyber Range console: brief, toolkit, cacao-client, cr-compile
        ├── evaluation_reporting/     # compiled-report ingest + training summary
        ├── scenario_selftest/        # deploy-time 16-step self-test + instructor smoke-test
        ├── all/                      # Kali rsyslog fix + command logging
        └── man/                      # syslog-ng forwarding (mgmt node)
```

## Topology

| Node | Role | Image / mgmt_user / flavor | IP (lab-net) |
|------|------|----------------------------|----------------|
| `ng-soar` | KMS + CACAO Validator/Executor (Docker) | ubuntu-noble-x86_64 / ubuntu / `standard.xsmedium` | 10.10.30.10 |
| `lab-target` | protected HTTP/SSH service **+ host-based enforcement (nftables input)** | ubuntu-noble-x86_64 / ubuntu / `standard.small` | 10.10.20.10 |
| `attacker` | suspicious traffic / malicious test IP | kali / debian / `standard.xmedium` | 10.10.10.10 |
| `student-ws` | Cyber Range trainee console (brief, toolkit, `cacao-client`, `cr-compile`) | ubuntu-noble-x86_64 / ubuntu / `standard.small` | 10.10.30.20 |
| `evaluation-reporting` | feedback & summary | ubuntu-noble-x86_64 / ubuntu / `standard.small` | 10.10.30.30 |
| `lab-router` **(ROUTER)** | Internet egress / default gateway | debian-12-x86_64 / debian / `standard.small` | 10.10.0.1 |

**One flat network:** `lab-net 10.10.0.0/16` (+ wan `100.100.100.0/24`).

The platform **isolates** sandbox networks — transit is not forwarded between
them by a multi-homed host nor by the per-network routers (confirmed by deploy
diagnostics). So all scenario hosts live on **one flat network** (`10.10.0.0/16`,
keeping their exact IPs), and the CACAO block is enforced **host-based on
`lab-target`** (nftables `input` drop on the malicious source IP), applied over
SSH and verified by driving the attacker at the target — all directly reachable
on the flat net. A single `lab-router` provides Internet egress.

`topology.yml` uses `groups: []`; plays target hosts by name and use the
platform auto-groups `hosts` / `routers` for the command-logging pass (same
convention as the reference sandbox).

## UML → resource mapping (all 16 steps covered)

| UML participant | Resource |
|-----------------|----------|
| NG-SOC Operator (Scenario Initiator) | instructor starting the training run on CyberRangeCZ |
| Student (Trainee) | trainee on `student-ws` (`cacao-client`) |
| NG-SOAR Operator | `soar-operator` account on `ng-soar` (`soar-operator` CLI, token-gated API) |
| Hands-on Educational Platform (Cyber Range) | CyberRangeCZ + `student-ws` (brief, toolkit, `cr-compile`) |
| NG-SOAR (KMS + CACAO Validator/Executor) | `ng-soar` `:9100` (`app.py`, KMS in `/var/log/ng-soar/kms`) |
| Attacker (malicious test IP) | `attacker` 10.10.10.10 |
| Lab Target Service (host firewall - nftables) | `lab-target` 10.10.20.10 (nginx + nftables `input`) |
| Evaluation/Reporting | `evaluation-reporting` `:9000` |

| # | UML step | Implemented by |
|---|----------|----------------|
| 1 | NG-SOC Op → Cyber Range: initiate exercise | training run / sandbox allocation; `common` marker `/etc/cacao-training.env` |
| 2 | Cyber Range → Attacker: suspicious traffic | `attacker` → `suspicious-traffic.service` (`/admin`, `/.env`, port 22 → lab-target) |
| 3 | Cyber Range → Student: exercise brief | `student_ws` → `~/cacao/EXERCISE_BRIEF.md` + `detected_traffic.log` |
| 4 | Student → NG-SOAR: create CACAO playbook | `cacao-client create` → `POST /playbooks` (KMS status `draft`) |
| 5 | Cyber Range → Student: templates, hints, commands | `student_ws/files/cacao-toolkit/` → `~/cacao/` |
| 6 | Student → NG-SOAR: submit for validation | `cacao-client submit` → `POST /playbooks/submit` |
| 7 | NG-SOAR: validate syntax, logic, params | `validate_cacao()` in `app.py` |
| 8 | NG-SOAR → Student: errors or approval | submit response (`approved`, `errors`, `warnings`, `attempt`, `status`) |
| 9 | Student → NG-SOAR: correct and resubmit | `cacao-client submit` again (status `rejected` → …) |
| 10 | NG-SOAR → NG-SOAR Operator: ready for execution | status `ready-for-execution`, `operator-notifications.log`, `soar-operator queue` |
| 11 | NG-SOAR Operator → NG-SOAR: execute | `soar-operator execute <id>` → `POST /operator/execute/<id>` (Student `/execute` → 403) |
| 12 | NG-SOAR → Lab Target: host firewall rule | SSH `soar-fw@lab-target`: `nft add rule inet filter input ip saddr <ip> counter drop` |
| 13 | NG-SOAR → Attacker → Lab Target: verify | probe from the attacker → `BLOCKED` |
| 14 | NG-SOAR → Student: logs, status, evidence | `cacao-client report` → `GET /playbooks/<id>/execution` |
| 15 | Cyber Range → Evaluation: compile | `cr-compile` (timer 30 s / `--now`) → `POST /ingest` |
| 16 | Evaluation → Student: training summary | `cacao-client summary` → `GET /summary` |

## NG-SOAR deployment

`docker_server` reproduces the reference `integrations` pattern: installs Docker
from the official Ubuntu repo, mounts the artefact **SMB share**, copies
`NG-SOAR.yml` to `/opt/NG-SOAR/docker-compose.yml`, logs in to Docker Hub and
runs it with `community.docker.docker_compose_v2` (`build: always`). If the SMB
share is unreachable, a **bundled fallback compose** (`docker_server/files/`)
brings up the KMS so the training still runs.

`ng_soar` then deploys the **KMS + CACAO Validator/Executor** container
(`/opt/ng-soar-cacao`, `:9100`) that provides the runnable storage/validation/
execution used by the 16-step flow, creates the **NG-SOAR Operator** account
(`soar-operator`, password in `vault.yml`, token in `/etc/ng-soar/operator.token`),
and generates the SSH keypair the executor uses to manage lab-target and attacker. In
production this front-ends the real NG-SOAR/SOARCA executor
(`:8080/trigger/playbook`).

## Command logging

`requirements.yml` pulls `cyberrangecz/ansible-role-sandbox-logging@v1.0.0`. The
last play of `playbook.yml` ("set up command logging") applies it to every Linux
`hosts`/`routers` node except Kali (with the
`slf_destination_port` 514/515 selection based on whether a `man` node exists),
and the `man` role configures syslog-ng forwarding — mirroring the reference.

## Deploy

```sh
# Instructor UI: register this Git repo as a Sandbox Definition. The platform
# reads topology.yml (root), builds the topology, generates the inventory, then
# runs provisioning/playbook.yml.

# On a Linux management host:
cd provisioning
ansible-galaxy install -r requirements.yml           # roles
ansible-galaxy collection install -r requirements-collections.yml # collections (local only)
ansible-playbook --syntax-check playbook.yml
```

## Run the CACAO workflow

Training definition: `V3_puc2-subcase2d-cacao-malicious-ip-block-training.json`.

```sh
# Student (student-ws)
cd ~/cacao
cp template_block_ip.json my_playbook.json
# edit: "id": "playbook--$(uuidgen)", source_ip 10.10.10.10
cacao-client create my_playbook.json        # UML 4  -> draft
cacao-client submit my_playbook.json        # UML 6-10 (fix errors, resubmit = UML 9)
cacao-client status my_playbook.json        # ready-for-execution

# NG-SOAR Operator (ssh soar-operator@10.10.30.10)
soar-operator queue                         # UML 10
soar-operator execute playbook--<uuid>      # UML 11-13

# Student again
cacao-client report my_playbook.json        # UML 14
cr-compile --now                            # UML 15 (also automatic every 30 s)
cacao-client summary                        # UML 16
```

A reference solution is provided at
`provisioning/roles/student_ws/files/cacao-toolkit/sample_block_ip_playbook.json`.
Instructor check (on ng-soar, before trainees start):
`sudo /usr/local/sbin/scenario-smoketest.sh`.

## Secrets management

Infrastructure values (Docker Hub PAT, SMB share, syslog collector, account
password hashes) are **centralised** in `provisioning/group_vars/all/vault.yml`,
aligned with the reference `integrations` branch so the sandbox deploys against
the same NG-SOC infra. The reference keeps these **inline and in plaintext**
across its roles; here they sit in one file so a single command protects them:

```sh
ansible-vault encrypt provisioning/group_vars/all/vault.yml
```

**Rotate the Docker Hub PAT and any account passwords before real use.** The
NG-SOAR executor uses an SSH keypair **generated at provisioning time** — no
private keys are committed.
