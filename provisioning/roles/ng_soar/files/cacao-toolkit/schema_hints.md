# CACAO 2.0 Schema Hints (UML step 5)

The NG-SOAR validator checks the following. Use these hints while authoring.

## Required top-level fields
| Field            | Rule                                                        |
|------------------|-------------------------------------------------------------|
| `type`           | must equal `"playbook"`                                      |
| `spec_version`   | must start with `cacao-2` (e.g. `"cacao-2.0"`)               |
| `id`             | `"playbook--<uuid-v4>"`                                      |
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

## Action step shape (firewall block)
```json
"action--block-ip": {
  "type": "action",
  "name": "Block source IP on the Lab Firewall",
  "on_completion": "end--01",
  "commands": [
    { "type": "ssh", "command": "sudo nft add rule inet filter forward ip saddr __SOURCE_IP__ counter drop" }
  ],
  "agent": "ng-soar--cacao-executor",
  "targets": ["lab-firewall"]
}
```

## Typical validation errors returned by NG-SOAR (UML step 8)
- `missing required field: 'workflow_start'`
- `'workflow_start' (...) does not reference an existing step`
- `no firewall *block/drop* command found in any action step`
- `required parameter missing: define a 'source_ip' playbook_variable ...`
