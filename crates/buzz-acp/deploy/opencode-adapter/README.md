# opencode ACP adapter (WO #598)

Host install path: `/opt/buzz/agents/opencode_acp.py`
Ox seat env: `/opt/buzz/personas/ox.env`

Agents cannot write `/opt/buzz` or restart systemd. After merge, root/Factory:

```sh
install -m 644 crates/buzz-acp/deploy/opencode-adapter/opencode_acp.py \
  /opt/buzz/agents/opencode_acp.py
# Append OPENCODE_TIMEOUT_SECS=2400 to ox.env if absent (see ox.env.append).
# Do not overwrite the rest of ox.env — it holds secrets.
systemctl restart buzz-agent@ox.service
```

Offline tests:

```
python3 -m unittest crates/buzz-acp/deploy/opencode-adapter/test_opencode_acp.py -v
```
