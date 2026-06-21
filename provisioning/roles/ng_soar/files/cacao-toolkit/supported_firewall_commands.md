# Supported Lab Firewall Commands (UML step 5)

The Lab Firewall runs **nftables** with a base `inet filter` table and a
`forward` chain. NG-SOAR executes the block command over SSH as the
`soar-fw` management user (passwordless sudo limited to `nft`).

## Block a source IP (the exercise goal)
```sh
sudo nft add rule inet filter forward ip saddr <SOURCE_IP> counter drop
```

## Other supported, validated commands
```sh
# Block a source IP only towards the protected service
sudo nft add rule inet filter forward ip saddr <SOURCE_IP> ip daddr 10.10.20.10 counter drop

# Reject instead of silently dropping
sudo nft add rule inet filter forward ip saddr <SOURCE_IP> counter reject

# Inspect / collect evidence
sudo nft list ruleset
sudo nft -a list chain inet filter forward

# Remove a rule by handle (rollback)
sudo nft delete rule inet filter forward handle <HANDLE>
```

## Notes
- The base policy of the `forward` chain is `accept`, so the attacker can reach
  the target until the block rule is applied (lets you verify before/after).
- `counter` keeps packet/byte counters so the executor can show evidence that
  the rule matched malicious traffic (UML step 14).
- Equivalent iptables form (for reference): `iptables -I FORWARD -s <SOURCE_IP> -j DROP`.
