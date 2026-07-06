# Supported Firewall Commands (UML step 5)

The block is enforced **host-based on the Lab Target Service** (`lab-target`,
10.10.20.10) using **nftables**, in the base `inet filter` table, on the
**`input`** chain. NG-SOAR executes the block over SSH as the `soar-fw`
management user (passwordless sudo limited to `nft`).

## Block a source IP (the exercise goal)
```sh
sudo nft add rule inet filter input ip saddr <SOURCE_IP> counter drop
```
The executor tags the rule with a comment `cacao-block-<SOURCE_IP>`.

## Other supported, validated commands
```sh
# Reject instead of silently dropping
sudo nft add rule inet filter input ip saddr <SOURCE_IP> counter reject

# Inspect / collect evidence
sudo nft list ruleset
sudo nft -a list chain inet filter input

# Remove a rule by handle (rollback)
sudo nft delete rule inet filter input handle <HANDLE>
```

## Notes
- The `input` chain filters packets destined TO the host, so dropping
  `ip saddr <SOURCE_IP>` there stops the malicious traffic arriving at the
  service. The base policy of `input` is `accept`, so the attacker can reach the
  target until the block rule is applied (lets you verify before/after).
- `counter` keeps packet/byte counters so the executor can show evidence that
  the rule matched malicious traffic (UML step 14).
- Equivalent iptables form (for reference): `iptables -I INPUT -s <SOURCE_IP> -j DROP`.
