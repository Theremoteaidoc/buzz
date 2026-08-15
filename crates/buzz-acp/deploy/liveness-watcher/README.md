# Out-of-process agent liveness watcher (WO #135)
#
# Separate process from any buzz-agent / buzz-acp event loop. Reads status-file
# mtimes under the per-host heartbeat directory and compares against systemd
# roster ground truth. Does NOT call touch_alive.
#
# Coverage is host-local: this unit only sees seats on the machine where it
# runs. Deploy one instance per host (ci-1, srv1389530, …). Each report JSON
# declares `coverage.scope=host-local` plus the authoritative seat list.
#
# Agents cannot write /opt/buzz or systemd. After merge, root/Factory installs:

```sh
install -d /opt/buzz/liveness-watcher
install -m 755 target/release/buzz-liveness-watcher /opt/buzz/bin/buzz-liveness-watcher
install -m 644 crates/buzz-acp/deploy/liveness-watcher/buzz-liveness-watcher.service \
  /etc/systemd/system/buzz-liveness-watcher.service
install -m 644 crates/buzz-acp/deploy/liveness-watcher/buzz-liveness-watcher.timer \
  /etc/systemd/system/buzz-liveness-watcher.timer
systemctl daemon-reload
systemctl enable --now buzz-liveness-watcher.timer
```

Offline tests (from repo root):

```
cargo test -p buzz-acp --test liveness_watcher -- --nocapture
cargo test -p buzz-acp liveness_watcher -- --nocapture
```
