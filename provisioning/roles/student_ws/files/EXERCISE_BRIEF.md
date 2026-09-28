# Exercise Brief — PUC2 Sub Case 2d (UML step 3)

## Scenario
A cyberattack is unfolding in the cyber range. The NG-SOC Operator has detected
**suspicious traffic originating from a malicious test IP** hitting the Lab
Target Service.

```
Malicious source IP : 10.10.10.10   (attacker)
Protected service   : http://10.10.20.10:80   (lab-target)
Enforcement point   : Lab Target Service host firewall (nftables input), managed by NG-SOAR
```

The detection evidence is at `~/cacao/detected_traffic.log` — the suspicious
requests seen from the malicious IP (sensitive-file probing such as `GET /admin`
and `GET /.env`, plus an SSH port-22 scan). Review it to understand what the
attacker is after.

## Your task
Author a **CACAO 2.0 playbook** that blocks the malicious source IP on the
**target host firewall** (nftables **input** drop rule on the Lab Target
Service), create it in **NG-SOAR** and get it validated. The **NG-SOAR
Operator** executes approved playbooks.

1. Use the materials the Cyber Range gave you (UML step 5):
   `template_block_ip.json`, `schema_hints.md`, `supported_firewall_commands.md`.
2. Copy the template to `~/cacao/my_playbook.json`, set a valid `id`
   (`playbook--<uuid-v4>`) and the `source_ip` to the malicious IP.
3. Create it in NG-SOAR (UML 4), submit it for validation (UML 6), fix any
   errors and resubmit (UML 9) until it is approved (UML 10).
4. After the NG-SOAR Operator executes it (UML 11-13), review the execution
   logs and host firewall evidence (UML 14) and your training summary (UML 16).

## Helper client
```sh
cacao-client create  ~/cacao/my_playbook.json   # UML 4
cacao-client submit  ~/cacao/my_playbook.json   # UML 6-10
cacao-client status  ~/cacao/my_playbook.json   # KMS status
cacao-client report  ~/cacao/my_playbook.json   # UML 14
cacao-client summary                            # UML 16
```

## Success criteria
- NG-SOAR returns `approved: true` and your playbook is `ready-for-execution`.
- After execution, the verification probe from the malicious IP reports
  `BLOCKED` and the host firewall evidence (`firewall_evidence`) shows your drop
  rule with the comment `cacao-block-10.10.10.10`.
- Your training summary grade is `PASS`.
