# PUC2 (CYNET) — Sub Case 2d: CACAO Playbook Authoring Training (Firewall IP Block)

A **CyberRangeCZ Sandbox Definition** that implements the full UML sequence for
*Sub Case 2d*: a trainee authors a **CACAO 2.0** playbook to block a malicious
source IP, **NG-SOAR** (KMS + CACAO Validator/Executor) validates and executes
it against the **Lab Firewall**, and the cyber range provides evaluation
feedback.

## Repository layout

```
.
├── topology.yml                      # Topology Definition (MUST be at root)
├── variables.yml                     # Optional APG variables (non-secret)
├── README.md
├── VALIDATION.md                     # Validation report
└── provisioning/
    ├── playbook.yml                  # Orchestrates roles over topology groups
    ├── requirements.yml              # Ansible collections
    ├── group_vars/all/
    │   ├── main.yml                  # Shared scenario facts (non-secret)
    │   └── vault.yml                 # Secret PLACEHOLDERS (encrypt with vault)
    └── roles/
        ├── common/                   # base packages, scenario markers
        ├── docker_server/            # Docker + NG-SOAR stack (reference pattern)
        ├── ng_soar/                  # KMS + CACAO Validator/Executor (CRITICAL)
        ├── lab_firewall/             # nftables gateway + NG-SOAR mgmt access
        ├── lab_target/               # protected HTTP/SSH service
        ├── attacker/                 # suspicious-traffic generator (test IP)
        ├── student_ws/               # brief + CACAO toolkit + cacao-client
        └── evaluation_reporting/     # feedback ingest + training summary
```

## Topology

| Node | Role | Networks (IP) | Flavor / Image |
|------|------|---------------|----------------|
| `ng-soar` | KMS + CACAO Validator/Executor (Docker) | soar-net (10.10.30.10) | standard.large / debian-12 |
| `lab-firewall` | nftables gateway (in attacker→target path) | soar-net .1, attacker-net .1, target-net .1 | standard.small / debian-12 |
| `lab-target` | protected HTTP/SSH service | target-net (10.10.20.10) | standard.small / debian-12 |
| `attacker` | suspicious traffic / malicious test IP | attacker-net (10.10.10.10) | standard.small / kali-2020.4 |
| `student-ws` | trainee authoring workstation | soar-net (10.10.30.20) | standard.small / debian-12 |
| `evaluation-reporting` | feedback & summary | soar-net (10.10.30.30) | standard.small / debian-12 |
| `soar/attacker/target-router` | WAN egress for provisioning | per-net .254 | standard.small / debian-12 |

**Networks (disjoint):** soar-net `10.10.30.0/24`, attacker-net `10.10.10.0/24`,
target-net `10.10.20.0/24`, wan `100.100.100.0/24`.

The **lab-firewall is connected to all three lab networks**, so every
attacker→target path crosses it. Provisioning installs static routes on
`attacker` and `lab-target` so inter-lab traffic is forced through the firewall,
making a source-IP block verifiable (UML step 13).

## UML → resource mapping (all 16 steps covered)

| # | UML step | Implemented by |
|---|----------|----------------|
| 1 | NG-SOC Op → Cyber Range: initiate exercise | Sandbox instantiation; `common` drops `/etc/cacao-training.env` marker |
| 2 | Cyber Range → Target: suspicious traffic from test IP | `attacker` role → `generate_suspicious_traffic.sh` + `suspicious-traffic.service` |
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

## Deploy

```sh
# In the CyberRangeCZ instructor UI: register this Git repo as a Sandbox Definition.
# The platform reads topology.yml (root), builds the topology, generates the
# inventory, then runs provisioning/playbook.yml.

# Local lint / dry-run:
cd provisioning
ansible-galaxy collection install -r requirements.yml
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

The reference NG-SOC role
([docker_server/tasks/main.yml](https://github.com/NG-SOC-eu/ng-soc-ansible/blob/central/provisioning/roles/docker_server/tasks/main.yml))
ships **hardcoded secrets in plaintext** — a user password hash, a Docker Hub
PAT, and SMB/host credentials. **This repo deliberately does NOT replicate
that.** All secrets are externalized to
`provisioning/group_vars/all/vault.yml` as inert `CHANGEME` placeholders, meant
to be encrypted with `ansible-vault encrypt` (or injected by the platform's
secret store). Docker Hub login is skipped while the PAT is `CHANGEME`, and the
NG-SOAR executor uses an **SSH keypair generated at provisioning time** (no
embedded private keys). Rotate/replace these before any real deployment.
```sh
ansible-vault encrypt provisioning/group_vars/all/vault.yml
```
