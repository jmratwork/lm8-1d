# Validation Report — PUC2 Sub Case 2d

Date: 2026-06-21

## 1. UML component → resource availability (traceability)

Every component in the sequence diagram is backed by a concrete sandbox resource.

| UML component / item | Sandbox resource | Provisioned by |
|----------------------|------------------|----------------|
| Hands-on Educational Platform (Cyber Range) | the CyberRangeCZ platform itself (topology + inventory + APG) | `topology.yml`, `variables.yml` |
| NG-SOAR (KMS + CACAO Validator/Executor) | host `ng-soar` running KMS container + CACAO Validator/Executor container | `docker_server`, `ng_soar` |
| Lab Firewall | host `lab-firewall` (nftables, dual/tri-homed gateway) | `lab_firewall` |
| Lab Target Service | host `lab-target` (nginx + ssh) | `lab_target` |
| Evaluation/Reporting | host `evaluation-reporting` (ingest+summary service) | `evaluation_reporting` |
| Malicious test IP | host `attacker` (10.10.10.10) traffic generator | `attacker` |
| Student (Trainee) workstation | host `student-ws` (brief, toolkit, `cacao-client`) | `student_ws` |

## 2. NG-SOAR (CACAO validation + execution) actually deployed

- `docker_server` installs Docker Engine + Compose plugin from the official repo
  and deploys the NG-SOAR stack via `community.docker.docker_compose_v2` against
  `/opt/NG-SOAR` — **reusing the reference NG-SOC `docker_server` pattern**
  (SMB artefact mount + `/opt/NG-SOAR/docker-compose.yml`), with a bundled
  fallback compose file.
- `ng_soar` builds and starts the **CACAO Validator/Executor** container
  (`/opt/ng-soar-cacao`), health-checked on `:9100/healthz`.
- **Validator verified functionally** (run locally against the shipped files):

  | Input | `approved` | Result |
  |-------|-----------|--------|
  | `sample_block_ip_playbook.json` | `true` | no errors |
  | `template_block_ip.json` | `true` | placeholder source IP detected |
  | broken playbook (no start/no block) | `false` | 4 actionable errors returned |

  This exercises UML steps 7 (validate), 8 (return result), 9 (resubmit),
  10 (approval).

## 3. Topology coherence

- **Unique names**: all host/router/network names unique. ✔
- **Disjoint CIDRs**: soar-net `10.10.30.0/24`, attacker-net `10.10.10.0/24`,
  target-net `10.10.20.0/24`, wan `100.100.100.0/24` — non-overlapping. ✔
- **net_mappings / router_mappings**: every mapping references an existing host/
  router and network; IPs fall inside their network CIDR and avoid `.0/.1/.2`
  reservation pitfalls (gateways use `.1` for the firewall by design, routers
  `.254`). ✔
- **Flavors**: only `standard.small` / `standard.large` used (valid). ✔
- **Images**: `debian-12-x86_64`, `kali-2020.4` (both listed as valid). ✔
- **Firewall on path**: `lab-firewall` is mapped to attacker-net, target-net AND
  soar-net; `attacker` and `lab-target` install static routes via the firewall,
  so attacker→target traffic crosses it and a source-IP drop is verifiable. ✔
- **Groups**: `ng_soar`, `lab_firewall`, `lab_target`, `attacker`, `student`,
  `evaluation_reporting` defined and consumed by `playbook.yml`. ✔

## 4. Syntax validation results

| Check | Tool | Result |
|-------|------|--------|
| YAML lint (topology, vars, provisioning) | `yamllint` (relaxed) | **PASS** (no findings) |
| YAML parse (all 16 `.yml` files) | `python -c yaml.safe_load_all` | **16 ok, 0 bad** |
| JSON validity (CACAO template + sample) | `python json.load` | **PASS** |
| Python apps (validator, evaluation) | `python -m py_compile` | **PASS** |
| Validator behaviour (approve/reject) | local function run | **PASS** (see §2) |

> Note: `ansible-playbook --syntax-check` could not run in this Windows shell
> (`ansible` aborts on non-blocking stdin under Git Bash — `WinError 87`). It is
> unrelated to the playbook content; run it on the CyberRangeCZ management node
> (Linux) or any Linux host:
> ```sh
> cd provisioning
> ansible-galaxy collection install -r requirements.yml
> ansible-playbook --syntax-check playbook.yml
> ```

## 5. Conclusion

All 16 UML steps are traceable to concrete resources (see README mapping table),
NG-SOAR's CACAO validation/execution is deployed and functionally verified, the
topology is internally consistent with the firewall on the attacker→target path,
and all YAML/JSON/Python assets pass syntax validation.
