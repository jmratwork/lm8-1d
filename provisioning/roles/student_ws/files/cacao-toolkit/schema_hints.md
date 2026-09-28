# CACAO 2.0 Schema Hints (UML step 5)

The NG-SOAR validator checks the following. Use these hints while authoring.

## Required top-level fields
| Field            | Rule                                                        |
|------------------|-------------------------------------------------------------|
| `type`           | must equal `"playbook"`                                      |
| `spec_version`   | must start with `cacao-2` (e.g. `"cacao-2.0"`)               |
| `id`             | `"playbook--<uuid-v4>"` (generate with `uuidgen`); it is also the NG-SOAR KMS key |
| `name`           | human-readable name                                         |
| `workflow_start` | id of the single `start` step                               |
| `workflow`       | non-empty object: `{ "<step-id>": { ...step... }, ... }`    |

## Workflow logic rules
- Exactly **one** `start` step and **at least one** `end` step.
- Every non-`end` step needs an `on_completion` pointing to an existing step id.
- At least one `action` step containing the firewall **block/drop** command.
- Valid step types: `start`, `end`, `action`, `if-condition`, `while-condition`,
  `switch-condition`, `parallel`, `playbook-action`.

## Required parameter
- Define a `source_ip` entry under `playbook_variables` **or** use the
  `__SOURCE_IP__` placeholder inside the block command. This is the malicious
  IP from the exercise brief.

## Action step shape (host-based block on the target)
```json
"action--block-ip": {
  "type": "action",
  "name": "Block source IP on the Lab Target Service",
  "on_completion": "end--01",
  "commands": [
    { "type": "ssh", "command": "sudo nft add rule inet filter input ip saddr __SOURCE_IP__ counter drop" }
  ],
  "agent": "ng-soar--cacao-executor",
  "targets": ["lab-target"]
}
```

## Life-cycle in NG-SOAR
1. `cacao-client create <file>` stores the playbook in the KMS as `draft` (UML 4).
   NG-SOAR refuses to store it if the `id` is not `playbook--<uuid-v4>`.
2. `cacao-client submit <file>` validates it (UML 6-8). Errors -> `rejected`;
   fix and resubmit (UML 9). Approved -> `ready-for-execution` and the NG-SOAR
   Operator is notified (UML 10).
3. Only the NG-SOAR Operator executes it (UML 11); then it becomes `executed`
   and `cacao-client report <file>` shows the evidence (UML 14).

## Typical validation errors returned by NG-SOAR (UML step 8)
- `missing required field: 'workflow_start'`
- `field 'id' must be a 'playbook--<uuid>' identifier`
- `step 'start--01': on_completion -> unknown step '...'`
- `'workflow_start' (...) does not reference an existing step`
- `no firewall *block/drop* command found in any action step`
- `required parameter missing: define a 'source_ip' playbook_variable ...`
