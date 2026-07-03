# Validation Report — PUC2 Sub Case 2d

Aligned with the reference sandbox
<https://github.com/NG-SOC-eu/ng-soc-ansible/tree/integrations>.

## 1. UML component → resource availability (traceability)

| UML component / item | Sandbox resource | Provisioned by |
|----------------------|------------------|----------------|
| Hands-on Educational Platform (Cyber Range) | the CyberRangeCZ platform | `topology.yml`, `variables.yml` |
| NG-SOAR (KMS + CACAO Validator/Executor) | host `ng-soar`: NG-SOAR stack (SMB/Docker) + CACAO Validator/Executor container | `docker_server`, `ng_soar` |
| Lab Firewall | host `lab-firewall` (nftables, tri-homed gateway) | `lab_firewall` |
| Lab Target Service | host `lab-target` (nginx + ssh) | `lab_target` |
| Evaluation/Reporting | host `evaluation-reporting` (ingest+summary) | `evaluation_reporting` |
| Malicious test IP | host `attacker` (10.10.10.10) | `attacker` |
| Student workstation | host `student-ws` (brief, toolkit, `cacao-client`) | `student_ws` |
| Command logging (platform) | `sandbox-logging` role + `man` syslog-ng | `all`, `man`, `requirements.yml` |

## 2. Alignment with the real infrastructure (integrations)

| Item | Reference (`integrations`) | This repo | Status |
|------|----------------------------|-----------|--------|
| Kali image / mgmt_user | `kali` / `debian` | `kali` / `debian` | ✔ aligned |
| Docker host | `ubuntu-noble-x86_64` / `ubuntu` / `standard.xsmedium` | idem for `ng-soar` | ✔ aligned |
| Server/victim image | `ubuntu-noble-x86_64` / `ubuntu` | idem for target/student/eval | ✔ aligned |
| Router image/flavor | `debian-12-x86_64` / `standard.small` | idem | ✔ aligned |
| NG-SOAR deploy | SMB → `/opt/NG-SOAR/docker-compose.yml` → `docker_compose_v2 build:always` | same, secrets via vault + bundled fallback | ✔ aligned |
| Docker Hub login | inline creds | `vault.yml` (same values) | ✔ aligned, externalised |
| Command logging | `sandbox-logging` v1.0.0 + `man` syslog-ng | `requirements.yml` + `all` + `man` roles | ✔ aligned |
| Secrets | inline plaintext | centralised in `vault.yml` (+ encrypt note) | ✔ aligned, hardened |

## 3. NG-SOAR (CACAO validation + execution) verified

- `docker_server` deploys NG-SOAR via the reference SMB+compose pattern.
- `ng_soar` builds the CACAO Validator/Executor (`:9100`), health-checked.
- Validator verified functionally against the shipped files:

  | Input | `approved` | Result |
  |-------|-----------|--------|
  | `sample_block_ip_playbook.json` | `true` | no errors |
  | `template_block_ip.json` | `true` | placeholder source IP detected |
  | broken playbook (no start/no block) | `false` | 4 actionable errors |

  Exercises UML steps 7 (validate), 8 (result), 9 (resubmit), 10 (approval).

## 4. Topology coherence

- Unique names; **CIDRs disjoint** (soar `10.10.30.0/24`, attacker `10.10.10.0/24`,
  target `10.10.20.0/24`, wan `100.100.100.0/24`). ✔
- Routers own `.1` (subnet gateway); firewall on `.254` of each net → **no
  collision** with reserved gateway/DHCP addresses. ✔
- Firewall tri-homed and on the attacker→target path; static routes force the
  data path through it → source-IP block verifiable (UML 13). ✔
- `groups: []` + hostname targeting → **no group/host name collision**. ✔
- Flavors/images from the reference catalogue (no unverified `standard.large`
  or `kali-2020.4`). ✔

## 5. Syntax validation results

| Check | Tool | Result |
|-------|------|--------|
| YAML parse (all 18 `.yml`) | `python yaml.safe_load_all` | **18 ok, 0 bad** |
| YAML lint | `yamllint` (relaxed) | PASS (1 cosmetic long-line, copied from reference) |
| JSON validity (CACAO template + sample) | `python json.load` | **PASS** |
| Python apps (validator, evaluation) | `python -m py_compile` | **PASS** |
| Validator behaviour (approve/reject) | local function run | **PASS** (see §3) |
| Stale refs (`groups['ng_soar']`, `eth2`, `/home/debian`) | grep | **none** |

> `ansible-playbook --syntax-check` / `ansible-lint` cannot run in this Windows
> shell (`WinError 87` / `No module named 'grp'` — Unix-only deps). Run on the
> CyberRangeCZ Linux management node:
> ```sh
> cd provisioning
> ansible-galaxy install -r requirements.yml
> ansible-galaxy collection install -r requirements.yml
> ansible-playbook --syntax-check playbook.yml
> ```

## 6. Training playthrough fixes (30-level training definition)

To keep every training level non-blocking on the deployed sandbox:

- **Symmetric routing** (`lab_routing` role + `host_vars/*`): soar-net hosts
  (`student-ws`, `ng-soar`, `evaluation-reporting`) get routes to both lab
  networks via the firewall `.254`, and `attacker`/`lab-target` get a return
  route to soar-net. Pure routing (no NAT) preserves source IPs. Routes are
  applied immediately and persisted via the `soar-lab-routes` systemd oneshot.
  The pre-existing attacker↔target routes are left untouched (disjoint sets).
  Unblocks levels 6, 23 (student-ws→target) and 26 (executor→attacker probe).
- **Detection evidence** (`~/cacao/detected_traffic.log`): lists the malicious
  requests (`GET /admin`, `GET /.env`, port-22 scan) so level 7 (`/.env`) is
  solvable from the workstation without touching attacker/target logs.
- **Honest verification** (`app.py`): a failed probe SSH is now reported as
  `inconclusive` instead of `blocked`, preventing a false `PASS` (level 29).

### Known non-blocking issue — cacao-roaster GUI (FIX 4, low priority)

The `cyentific/cacao-roaster` container (KMS/GUI on `:3000`) reports
`unhealthy`. **Decision: left as-is, non-blocking.** Rationale: the container is
defined in the private `NG-SOAR.yml` pulled from the artefact SMB share, **not**
in this repo, so its healthcheck cannot be patched here; and **no training level
uses the GUI** — the 30-level training drives the CLI/API (`cacao-client` →
NG-SOAR `:9100`), which is healthy. Recommended fix on the artefact side:
widen the healthcheck `start_period` (the SPA is slow to warm up) or correct its
health endpoint. If the GUI is never needed, gate that service out of
`NG-SOAR.yml`.

## 7. Conclusion

All 16 UML steps are traceable to concrete resources; infrastructure choices
(images, flavors, mgmt_user, NG-SOAR Docker deployment, command logging,
secrets) are aligned with the real `integrations` sandbox; the topology is
coherent with the firewall on the attacker→target path; and all YAML/JSON/Python
assets pass local validation. Remaining checks (`--syntax-check`, live deploy)
must run on a Linux management node.
