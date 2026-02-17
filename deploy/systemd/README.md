# Rusty Pinch systemd profile

## Files

- `rusty-pinch-telegram.service`: Telegram channel worker service.
- `rusty-pinch-whatsapp.service`: WhatsApp bridge worker service.
- `rusty-pinch.env.example`: shared env file template for both services.

## Install steps

1. Copy package to `/opt/rusty-pinch`.
2. Copy env template and set secrets:

```bash
sudo mkdir -p /etc/rusty-pinch /var/lib/rusty-pinch/{data,workspace}
sudo cp rusty-pinch/deploy/systemd/rusty-pinch.env.example /etc/rusty-pinch/rusty-pinch.env
sudo chown -R rusty-pinch:rusty-pinch /var/lib/rusty-pinch
```

3. Install unit files:

```bash
sudo cp rusty-pinch/deploy/systemd/rusty-pinch-telegram.service /etc/systemd/system/
sudo cp rusty-pinch/deploy/systemd/rusty-pinch-whatsapp.service /etc/systemd/system/
sudo systemctl daemon-reload
```

4. Enable and start services:

```bash
sudo systemctl enable --now rusty-pinch-telegram
# optional while WhatsApp stays in community test
sudo systemctl enable --now rusty-pinch-whatsapp
```

## Operational checks

```bash
sudo systemctl status rusty-pinch-telegram --no-pager
journalctl -u rusty-pinch-telegram -f
```

Expect startup log event `channel_start` and turn logs with `event=turn`.
