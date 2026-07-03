# PUC2 (CYNET) — Sub Case 2d: CACAO Playbook Authoring Training (Firewall IP Block)

A **CyberRangeCZ Sandbox Definition** that implements the full UML sequence for
*Sub Case 2d*: a trainee authors a **CACAO 2.0** playbook to block a malicious
source IP, **NG-SOAR** (KMS + CACAO Validator/Executor) validates and executes
it against the **Lab Firewall**, and the cyber range provides evaluation
feedback.

Infrastructure conventions (images, flavors, `mgmt_user`, Docker/NG-SOAR
deployment, command logging, secrets) are aligned with the real NG-SOC sandbox:
<https://github.com/NG-SOC-eu/ng-soc-ansible/tree/integrations>.

## Repository layout

```
.
├── topology.yml                      # Topology Definition (MUST be at root)
├── variables.yml                     # APG variables (variant answers)
├── README.md
├── VALIDATION.md                     # Validation report
└── provisioning/
    ├── playbook.yml                  # Orchestrates roles (hostname targeting)
    ├── requirements.yml              # sandbox-logging role + collections
    ├── group_vars/all/
    │   ├── main.yml                  # Shared scenario facts (non-secret)
    │   └── vault.yml                 # Secrets (encrypt with ansible-vault)
    └── roles/
        ├── common/                   # base packages, scenario markers
        ├── docker_server/            # Docker + NG-SOAR stack (integrations pattern)
        ├── ng_soar/                  # KMS + CACAO Validator/Executor + toolkit
        ├── lab_firewall/             # nftables gateway + NG-SOAR mgmt access
        ├── lab_target/               # protected HTTP/SSH service
        ├── attacker/                 # suspicious-traffic generator (test IP)
        ├── student_ws/               # brief + CACAO toolkit + cacao-client
        ├── evaluation_reporting/     # feedback ingest + training summary
        ├── all/                      # Kali rsyslog fix + command logging
        └── man/                      # syslog-ng forwarding (mgmt node)
```

## Topology

| Node | Role | Image / mgmt_user / flavor | Networks (IP) |
|------|------|----------------------------|----------------|
| `ng-soar` | KMS + CACAO Validator/Executor (Docker) | ubuntu-noble-x86_64 / ubuntu / `standard.xsmedium` | soar-net 10.10.30.10 |
| `lab-firewall` | nftables gateway (attacker→target path) | debian-12-x86_64 / debian / `standard.small` | soar .254, attacker .254, target .254 |
| `lab-target` | protected HTTP/SSH service | ubuntu-noble-x86_64 / ubuntu / `standard.small` | target-net 10.10.20.10 |
| `attacker` | suspicious traffic / malicious test IP | kali / debian / `standard.xmedium` | attacker-net 10.10.10.10 |
| `student-ws` | trainee authoring workstation | ubuntu-noble-x86_64 / ubuntu / `standard.small` | soar-net 10.10.30.20 |
| `evaluation-reporting` | feedback & summary | ubuntu-noble-x86_64 / ubuntu / `standard.small` | soar-net 10.10.30.30 |
| `soar/attacker/target-router` | WAN egress + subnet gateway (.1) | debian-12-x86_64 / debian / `standard.small` | per-net .1 |

**Networks (disjoint):** soar-net `10.10.30.0/24`, attacker-net `10.10.10.0/24`,
target-net `10.10.20.0/24`, wan `100.100.100.0/24`.

Each router owns `.1` (the subnet gateway, as the platform/OpenStack expects).
The **lab-firewall is connected to all three lab networks at `.254`**, so every
attacker→target path crosses it. Provisioning installs static routes on
`attacker` and `lab-target` so inter-lab traffic is forced through the firewall,
making a source-IP block verifiable (UML step 13); Internet egress for
provisioning stays via each network's router.

`topology.yml` uses `groups: []`; plays target hosts by name and use the
platform auto-groups `hosts` / `routers` for the command-logging pass (same
convention as the reference sandbox).

## UML → resource mapping (all 16 steps covered)

| # | UML step | Implemented by |
|---|----------|----------------|
| 1 | NG-SOC Op → Cyber Range: initiate exercise | Sandbox instantiation; `common` drops `/etc/cacao-training.env` marker |
| 2 | Cyber Range → Target: suspicious traffic from test IP | `attacker` → `generate_suspicious_traffic.sh` + `suspicious-traffic.service` |
| 3 | Cyber Range → Student: exercise brief | `student_ws` → `EXERCISE_BRIEF.md` in `~/cacao/` |
| 4 | Student → Cyber Range: create CACAO playbook | `student_ws` workspace `~/cacao/` + `template_block_ip.json` |
| 5 | Cyber Range → Student: templates, schema hints, firewall commands | `ng_soar` toolkit (served via KMS) + local copy: `template_block_ip.json`, `schema_hints.md`, `supported_firewall_commands.md` |
| 6 | Student → Cyber Range: submit for validation | `cacao-client validate` → `POST /validate` on NG-SOAR |
| 7 | NG-SOAR: validate syntax, workflow logic, params | `ng_soar` CACAO Validator → `validate_cacao()` in `app.py` |
| 8 | NG-SOAR → Student: validation result | `/validate` response (errors/approval) |
| 9 | Student → NG-SOAR: correct & resubmit | re-run `cacao-client validate` after edits |
| 10 | NG-SOAR → Student: approved, ready to execute | `approved: true` verdict from validator |
| 11 | Student → NG-SOAR: execute validated playbook | `cacao-client execute` → `POST /execute` |
| 12 | NG-SOAR → Lab Firewall: apply block rule | `execute_cacao()` SSH `nft add rule ... saddr <ip> drop` |
| 13 | NG-SOAR → Lab Target: verify traffic blocked | executor drives attacker probe; `blocked: true` |
| 14 | NG-SOAR → Student: logs, status, evidence | `/execute` response: log, `firewall_evidence` (nft ruleset), status |
| 15 | NG-SOAR → Evaluation/Reporting: compile report | executor `POST /ingest` on evaluation host |
| 16 | Evaluation/Reporting → Student: training summary | `cacao-client summary` → `GET /summary` |

## NG-SOAR deployment

`docker_server` reproduces the reference `integrations` pattern: installs Docker
from the official Ubuntu repo, mounts the artefact **SMB share**, copies
`NG-SOAR.yml` to `/opt/NG-SOAR/docker-compose.yml`, logs in to Docker Hub and
runs it with `community.docker.docker_compose_v2` (`build: always`). If the SMB
share is unreachable, a **bundled fallback compose** (`docker_server/files/`)
brings up the KMS so the training still runs.

`ng_soar` then deploys the **CACAO Validator/Executor** container
(`/opt/ng-soar-cacao`, `:9100`) that provides the runnable validation/execution
used by the 16-step flow, publishes the CACAO toolkit through the KMS, and
generates the SSH keypair the executor uses to manage the Lab Firewall. In
production this front-ends the real NG-SOAR/SOARCA executor
(`:8080/trigger/playbook`).

## Command logging

`requirements.yml` pulls `cyberrangecz/ansible-role-sandbox-logging@v1.0.0`. The
`all` role applies it to every Linux `hosts`/`routers` node (with the
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
ansible-galaxy collection install -r requirements.yml # collections
ansible-playbook --syntax-check playbook.yml
```

## Run the CACAO workflow (from student-ws)

```sh
cd ~/cacao
cp template_block_ip.json my_playbook.json
# edit my_playbook.json: set a real "id" and source_ip 10.10.10.10
cacao-client validate my_playbook.json      # UML 6,7,8 (fix errors, resubmit = UML 9)
cacao-client execute  my_playbook.json      # UML 11,12,13,14
cacao-client summary                        # UML 16
```

A reference solution is provided at
`provisioning/roles/ng_soar/files/cacao-toolkit/sample_block_ip_playbook.json`.

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
