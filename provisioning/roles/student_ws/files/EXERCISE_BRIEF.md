# Exercise Brief — PUC2 Sub Case 2d (UML step 3)

## Scenario
A cyberattack is unfolding in the cyber range. The NG-SOC Operator has detected
**suspicious traffic originating from a malicious test IP** hitting the Lab
Target Service.

```
Malicious source IP : 10.10.10.10   (attacker)
Protected service   : http://10.10.20.10:80   (lab-target)
Enforcement point   : Lab Target Service (nftables input)  managed by NG-SOAR
```

NG-SOC has attached the observed detection evidence at
`~/cacao/detected_traffic.log` — the suspicious requests seen from the malicious
IP (sensitive-file probing such as `GET /admin` and `GET /.env`, plus an SSH
port-22 scan). Review it to understand what the attacker is after.

## Your task
Author a **CACAO 2.0 playbook** that blocks the malicious source IP with an
nftables **input** drop rule on the **Lab Target Service**, then have **NG-SOAR
validate and execute** it.

1. Start from the template: `~/cacao/template_block_ip.json` (UML step 5).
2. Read the schema hints (`~/cacao/schema_hints.md`) and the supported firewall
   commands (`~/cacao/supported_firewall_commands.md`).
3. Fill in a valid `id`, and set the `source_ip` to the malicious IP.
4. Submit it for validation; fix any errors NG-SOAR reports and resubmit.
5. Once approved, execute it and confirm the malicious traffic is blocked.

## Helper client
A wrapper around the NG-SOAR CACAO API is installed as `cacao-client`:

```sh
cacao-client validate ~/cacao/my_playbook.json     # UML steps 6,7,8
cacao-client execute  ~/cacao/my_playbook.json     # UML steps 11-14
cacao-client summary                               # UML step 16
```

## Success criteria
- NG-SOAR returns `approved: true` for your playbook.
- After execution, the verification probe from the attacker host reports
  `blocked` and the target's ruleset (`firewall_evidence`) shows your drop rule
  with the comment `cacao-block-10.10.10.10`.
