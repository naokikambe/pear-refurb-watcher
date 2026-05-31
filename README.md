# pear-refurb-watcher

Generic web refurb monitor.

This public repository is the watcher half of a two-repository monitoring setup:

- `pear-refurb-watcher`: fetches pages, detects changes, owns encrypted state.
- `pear-refurb-notifier`: receives encrypted dispatch payloads and sends email.

No monitored URL, site-specific selector, notification content, recipient, token, key, HTML, page text, or plaintext state should be committed to either repository.

## Architecture

```text
pear-refurb-watcher
  -> encrypted_state.json in a Secret Gist
  -> repository_dispatch with encrypted payload
  -> pear-refurb-notifier
  -> Resend API
```

The watcher does not send email. The notifier does not fetch websites, read the Secret Gist, or keep state.

## Secrets

Configure these GitHub Secrets in the watcher repository:

```text
MONITOR_TARGETS
STATE_ENCRYPTION_KEY
PAYLOAD_ENCRYPTION_KEY
STATE_GIST_ID
STATE_GIST_TOKEN
DISPATCH_TOKEN
DISPATCH_REPO
```

`PAYLOAD_ENCRYPTION_KEY` must also be configured in the notifier repository with the same value. `STATE_ENCRYPTION_KEY` is watcher-only.

Generate Fernet keys with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Store keys only in GitHub Secrets. Do not print them in logs or put sample key values in documentation.

`DISPATCH_TOKEN` must be able to call the GitHub repository dispatch API for `DISPATCH_REPO`. For fine-grained tokens, grant the minimum permissions required for repository dispatch. Do not use a broad token unless necessary, and store it only in GitHub Secrets.

Security note: Do not enable GitHub Actions debug logging in public repositories when using this project.

Avoid setting `ACTIONS_RUNNER_DEBUG` or `ACTIONS_STEP_DEBUG` to `true`, because debug logs may include additional execution details. This project intentionally avoids logging decrypted payloads, notification bodies, URLs, credentials, recipient information, and plaintext state.

## MONITOR_TARGETS

`MONITOR_TARGETS` is a JSON array string. It is the only place where target URLs, site-specific selectors, field mappings, and retention settings belong.

```json
[
  {
    "id": "source-a",
    "label": "Display Name",
    "url": "https://example.com/products",
    "mode": "item_list",
    "item_selectors": [".product-card"],
    "item_key_strategy": "link_hash",
    "fields": {
      "title": ".title",
      "spec": ".spec",
      "price": ".price",
      "url": {
        "selector": "a",
        "attr": "href"
      }
    },
    "notify_on": ["added", "changed"],
    "update_state_on_non_notified_change": false,
    "history_max_items": 1000,
    "max_notify_items": 20
  }
]
```

Use abstract IDs. Target IDs may appear in logs and encrypted plaintext payload after decryption by the notifier, so avoid names that reveal the monitored source. `label` is optional and is used as the human-readable source name in notifications. If `label` is omitted, the watcher uses the target ID as the source label.

Each `fields` value can be either a non-empty CSS selector string or an object:

```json
{
  "selector": ".value",
  "attr": "href",
  "regex": "pattern with a capture group",
  "group": 1
}
```

Use `":self"` when the item node itself should be used as the field value source. This is useful when `item_selectors` selects links directly:

```json
{
  "title": { "selector": ":self" },
  "url": { "selector": ":self", "attr": "href" }
}
```

Use `attr` for attributes such as links. URL fields and `href` attributes are normalized with `strip_query_params` before they are included in notification payloads. Use `regex` only when a selected text contains multiple values and one field must be extracted from it. Empty field selectors are rejected.

## State

Runtime state is not committed. The watcher reads and writes `encrypted_state.json` in a Secret Gist.

Secret Gists are not strict private storage: anyone with the URL may be able to access them. For that reason, only encrypted state is stored there. Gist revisions can retain older encrypted blobs, so plaintext must never be written to the Gist.

Plaintext state exists only in memory during the workflow and contains hash data only:

```json
{
  "version": 1,
  "targets": {
    "source-a": {
      "mode": "item_list",
      "current": {
        "items": {
          "sha256:item-id": "sha256:fingerprint"
        }
      },
      "history": {
        "recent_item_ids": [
          "sha256:item-id"
        ]
      }
    }
  }
}
```

State may contain target IDs, modes, item ID hashes, fingerprint hashes, and rolling history hashes. It must not contain URLs, names, prices, specs, HTML, text fragments, notification bodies, recipients, timestamps, or plaintext payloads.

## Notifications

When a target has a notification-worthy change, the watcher creates a plaintext payload in memory, encrypts it with `PAYLOAD_ENCRYPTION_KEY`, and sends only this dispatch body:

```json
{
  "event_type": "notify",
  "client_payload": {
    "encrypted": true,
    "ciphertext": "..."
  }
}
```

The encrypted payload contains an `event_id`, `detected_at`, source IDs, source labels, counts, and up to `max_notify_items` item details. The plaintext payload is never logged.

`removed` events can be counted, but removed item details may be unavailable. Removed items are absent from the current page, and plaintext item details are not stored in state, so a removed notification may contain only the source ID and `change: removed`. For detailed notifications, `added` and `changed` are the primary use cases.

Notification ordering is at-least-once oriented:

1. Fetch pages.
2. Detect diffs.
3. Build notification payload.
4. Encrypt payload.
5. Send `repository_dispatch`.
6. Save encrypted state to the Secret Gist.

If dispatch fails, state is not updated. If dispatch succeeds but Gist update fails, the next run may dispatch the same notification again. Exactly-once notification is not guaranteed.

## Payload Size

GitHub repository dispatch payloads have size limits. The watcher limits item details per target with `max_notify_items`, default `20`.

If the encrypted dispatch body approaches the safety limit, item details are trimmed and the payload marks the target as:

```json
{
  "truncated": true,
  "included_count": 20,
  "total_count": 42
}
```

If the encrypted payload is still too large after trimming, the workflow fails and state is not updated.

## history_max_items

`history_max_items` is a watcher-side state retention policy.

- Target-level setting.
- Default: `1000`.
- `0` disables rolling history.
- `history.recent_item_ids` stores only item ID hashes.
- Oldest entries are dropped first.
- The notifier does not know about or manage history.

## update_state_on_non_notified_change

For `item_list`, removed-only changes often create notification noise.

- `false` default: non-notified changes do not update encrypted state.
- `true`: non-notified changes update encrypted state, but do not dispatch email payloads.

The `true` setting can improve reappearance detection but increases Secret Gist writes.

## Modes

- `full_text`: hash normalized page text after noise removal.
- `selected_text`: hash only CSS selector matches.
- `item_list`: hash item IDs and item fingerprints.
- `auto`: uses `item_list` if `item_selectors` exists, `selected_text` if `selectors` exists, otherwise `full_text`.

The default User-Agent is neutral:

```text
Mozilla/5.0 (compatible; GenericWebMonitor/1.0)
```

## Noise Reduction

The watcher removes these selectors by default:

```text
script, style, noscript, svg, canvas, iframe, header, footer, nav, form, aside, template,
[aria-hidden="true"], .visually-hidden, .sr-only, .screen-reader-only
```

It also removes likely cookie or overlay elements when their `class` or `id` contains:

```text
cookie, consent, banner, modal, popup
```

Use `selectors`, `item_selectors`, and `ignore_patterns` to reduce noisy diffs. `item_list` with `link_hash` is often more stable for card/list pages. If the item node itself is a link, `link_hash` uses that link; otherwise it uses the first descendant link.

## GitHub Actions

The default schedule is 10 minutes and avoids minute `00`:

```yaml
7,17,27,37,47,57 * * * *
```

GitHub Actions cron is best-effort and may be delayed or skipped. Avoid excessive monitoring frequency and excessive access to target sites.

## Secret Gist Token Notes

`STATE_GIST_TOKEN` must be able to read and update the configured Secret Gist. Treat it as dedicated to encrypted state storage, prefer a dedicated token or account where possible, and do not reuse a broadly privileged personal token. Never log the token. Only encrypted state is written to the Gist.

## Limitations

- Dynamic sites can produce false positives or missed changes.
- This setup does not guarantee exactly-once email delivery.
- Resend delivery depends on the notifier repository and Resend account state.
- Gist API or repository dispatch failures fail the watcher workflow.

## Public Release Checklist

- No real target URL appears in the repository.
- No real selector or source name appears in the repository.
- `encrypted_state.json` in the Gist is encrypted.
- Dispatch payload contains ciphertext only.
- Logs do not print URLs, notification content, keys, tokens, recipients, or detected timestamps.
- `git log --all --oneline --decorate` contains neutral messages.

## License

MIT
