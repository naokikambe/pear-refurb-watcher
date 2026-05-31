from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup, Tag
from cryptography.fernet import Fernet, InvalidToken


TARGETS_ENV = "MONITOR_TARGETS"
STATE_FILE_NAME = "encrypted_state.json"
TIMEOUT_SECONDS = 15
USER_AGENT = "Mozilla/5.0 (compatible; GenericWebMonitor/1.0)"
DISPATCH_BODY_LIMIT_BYTES = 60_000

DEFAULT_EXCLUDE_SELECTORS = [
    "script",
    "style",
    "noscript",
    "svg",
    "canvas",
    "iframe",
    "header",
    "footer",
    "nav",
    "form",
    "aside",
    "template",
    '[aria-hidden="true"]',
    ".visually-hidden",
    ".sr-only",
    ".screen-reader-only",
]
NOISE_ATTR_RE = re.compile(r"(cookie|consent|banner|modal|popup)", re.IGNORECASE)
VALID_MODES = {"auto", "full_text", "selected_text", "item_list"}
VALID_ITEM_KEY_STRATEGIES = {"content_hash", "link_hash", "text_hash"}
VALID_NOTIFY_ON = {"any_change", "added", "removed", "changed"}


class MonitorError(RuntimeError):
    pass


@dataclass
class TargetConfig:
    id: str
    url: str
    label: str = ""
    mode: str = "auto"
    selectors: list[str] = field(default_factory=list)
    exclude_selectors: list[str] = field(default_factory=list)
    ignore_patterns: list[str] = field(default_factory=list)
    item_selectors: list[str] = field(default_factory=list)
    item_exclude_selectors: list[str] = field(default_factory=list)
    item_key_strategy: str = "content_hash"
    notify_on: list[str] = field(default_factory=list)
    update_state_on_non_notified_change: bool = False
    strip_query_params: list[str] = field(default_factory=list)
    fields: dict[str, Any] = field(default_factory=dict)
    notification_sort_rules: list[dict[str, Any]] = field(default_factory=list)
    history_max_items: int = 1000
    max_notify_items: int = 20

    @property
    def effective_mode(self) -> str:
        if self.mode != "auto":
            return self.mode
        if self.item_selectors:
            return "item_list"
        if self.selectors:
            return "selected_text"
        return "full_text"

    @property
    def effective_notify_on(self) -> set[str]:
        if self.notify_on:
            return set(self.notify_on)
        if self.effective_mode == "item_list":
            return {"added", "changed"}
        return {"any_change"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_value(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def env_required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise MonitorError(f"{name} is not set")
    return value


def fernet_from_env(name: str) -> Fernet:
    try:
        return Fernet(env_required(name).encode("utf-8"))
    except ValueError as exc:
        raise MonitorError(f"{name} is invalid") from exc


def encrypt_json(payload: dict[str, Any], fernet: Fernet) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return fernet.encrypt(raw).decode("utf-8")


def decrypt_json(ciphertext: str, fernet: Fernet) -> dict[str, Any]:
    try:
        raw = fernet.decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise MonitorError("Failed to decrypt state") from exc
    return json.loads(raw.decode("utf-8"))


def require_string_list(value: Any, field_name: str, target_id: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise MonitorError(f"Target {target_id} has invalid {field_name}")
    return value


def require_int(value: Any, field_name: str, target_id: str, default: int) -> int:
    if value is None:
        return default
    if not isinstance(value, int) or value < 0:
        raise MonitorError(f"Target {target_id} has invalid {field_name}")
    return value


def require_sort_rules(value: Any, target_id: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise MonitorError(f"Target {target_id} has invalid notification_sort_rules")
    rules: list[dict[str, Any]] = []
    for rule in value:
        if not isinstance(rule, dict):
            raise MonitorError(f"Target {target_id} has invalid notification_sort_rules")
        label = rule.get("label")
        match = rule.get("match")
        if not isinstance(label, str) or not label.strip():
            raise MonitorError(f"Target {target_id} has invalid notification_sort_rules")
        if not isinstance(match, list) or not match or not all(isinstance(item, str) and item for item in match):
            raise MonitorError(f"Target {target_id} has invalid notification_sort_rules")
        rules.append({"label": label, "match": match})
    return rules


def load_targets() -> list[TargetConfig]:
    raw = env_required(TARGETS_ENV)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MonitorError(f"{TARGETS_ENV} must be a JSON array") from exc
    if not isinstance(payload, list) or not payload:
        raise MonitorError(f"{TARGETS_ENV} must be a non-empty JSON array")

    seen_ids: set[str] = set()
    targets: list[TargetConfig] = []
    for index, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            raise MonitorError(f"Target #{index} must be an object")

        target_id = item.get("id")
        label = item.get("label")
        url = item.get("url")
        if not isinstance(target_id, str) or not target_id.strip():
            raise MonitorError(f"Target #{index} has an invalid id")
        if label is None:
            label = target_id
        if not isinstance(label, str) or not label.strip():
            raise MonitorError(f"Target {target_id} has an invalid label")

        parsed_url = urlparse(url) if isinstance(url, str) else None
        if parsed_url is None or parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
            raise MonitorError(f"Target {target_id} has an invalid url")
        if target_id in seen_ids:
            raise MonitorError(f"Duplicate target id: {target_id}")

        mode = item.get("mode", "auto")
        item_key_strategy = item.get("item_key_strategy", "content_hash")
        notify_on = require_string_list(item.get("notify_on"), "notify_on", target_id)
        fields = item.get("fields", {})
        if mode not in VALID_MODES:
            raise MonitorError(f"Target {target_id} has invalid mode")
        if item_key_strategy not in VALID_ITEM_KEY_STRATEGIES:
            raise MonitorError(f"Target {target_id} has invalid item_key_strategy")
        if any(value not in VALID_NOTIFY_ON for value in notify_on):
            raise MonitorError(f"Target {target_id} has invalid notify_on")
        if not isinstance(fields, dict) or not all(isinstance(k, str) for k in fields):
            raise MonitorError(f"Target {target_id} has invalid fields")
        for value in fields.values():
            if isinstance(value, str):
                if not value:
                    raise MonitorError(f"Target {target_id} has invalid fields")
                continue
            if not isinstance(value, dict) or not isinstance(value.get("selector"), str):
                raise MonitorError(f"Target {target_id} has invalid fields")
            if not value["selector"]:
                raise MonitorError(f"Target {target_id} has invalid fields")
            if "attr" in value and not isinstance(value["attr"], str):
                raise MonitorError(f"Target {target_id} has invalid fields")
            if "regex" in value and not isinstance(value["regex"], str):
                raise MonitorError(f"Target {target_id} has invalid fields")
            if "group" in value and not isinstance(value["group"], int):
                raise MonitorError(f"Target {target_id} has invalid fields")

        config = TargetConfig(
            id=target_id,
            label=label,
            url=url,
            mode=mode,
            selectors=require_string_list(item.get("selectors"), "selectors", target_id),
            exclude_selectors=require_string_list(item.get("exclude_selectors"), "exclude_selectors", target_id),
            ignore_patterns=require_string_list(item.get("ignore_patterns"), "ignore_patterns", target_id),
            item_selectors=require_string_list(item.get("item_selectors"), "item_selectors", target_id),
            item_exclude_selectors=require_string_list(item.get("item_exclude_selectors"), "item_exclude_selectors", target_id),
            item_key_strategy=item_key_strategy,
            notify_on=notify_on,
            update_state_on_non_notified_change=bool(item.get("update_state_on_non_notified_change", False)),
            strip_query_params=require_string_list(item.get("strip_query_params"), "strip_query_params", target_id),
            fields=fields,
            notification_sort_rules=require_sort_rules(item.get("notification_sort_rules"), target_id),
            history_max_items=require_int(item.get("history_max_items"), "history_max_items", target_id, 1000),
            max_notify_items=require_int(item.get("max_notify_items"), "max_notify_items", target_id, 20),
        )
        if config.effective_mode == "selected_text" and not config.selectors:
            raise MonitorError(f"Target {target_id} selected_text mode requires selectors")
        if config.effective_mode == "item_list" and not config.item_selectors:
            raise MonitorError(f"Target {target_id} item_list mode requires item_selectors")

        seen_ids.add(target_id)
        targets.append(config)

    return targets


def default_state() -> dict[str, Any]:
    return {"version": 1, "targets": {}}


def gist_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def load_encrypted_state(fernet: Fernet) -> dict[str, Any]:
    gist_id = env_required("STATE_GIST_ID")
    token = env_required("STATE_GIST_TOKEN")
    response = requests.get(
        f"https://api.github.com/gists/{gist_id}",
        headers=gist_headers(token),
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code == 404:
        return default_state()
    try:
        response.raise_for_status()
    except requests.RequestException:
        raise MonitorError("Failed to load encrypted state") from None

    content = response.json().get("files", {}).get(STATE_FILE_NAME, {}).get("content", "").strip()
    if not content or content == "{}":
        return default_state()
    state = decrypt_json(content, fernet)
    if not isinstance(state, dict) or state.get("version") != 1:
        raise MonitorError("State has an unsupported format")
    state.setdefault("targets", {})
    return state


def save_encrypted_state(state: dict[str, Any], fernet: Fernet) -> None:
    gist_id = env_required("STATE_GIST_ID")
    token = env_required("STATE_GIST_TOKEN")
    ciphertext = encrypt_json(state, fernet)
    response = requests.patch(
        f"https://api.github.com/gists/{gist_id}",
        headers=gist_headers(token),
        json={"files": {STATE_FILE_NAME: {"content": ciphertext + "\n"}}},
        timeout=TIMEOUT_SECONDS,
    )
    try:
        response.raise_for_status()
    except requests.RequestException:
        raise MonitorError("Failed to save encrypted state") from None


def fetch_html(session: requests.Session, target: TargetConfig) -> str:
    try:
        response = session.get(target.url, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
    except requests.RequestException:
        raise MonitorError(f"Failed to fetch target {target.id}") from None
    return response.text


def safe_select(node: BeautifulSoup | Tag, selector: str, target_id: str) -> list[Tag]:
    try:
        return list(node.select(selector))
    except Exception:
        raise MonitorError(f"Target {target_id} has an invalid selector") from None


def safe_select_one(node: BeautifulSoup | Tag, selector: str, target_id: str) -> Tag | None:
    try:
        return node.select_one(selector)
    except Exception:
        raise MonitorError(f"Target {target_id} has an invalid selector") from None


def remove_noise(soup: BeautifulSoup | Tag, exclude_selectors: list[str], target_id: str) -> None:
    for selector in [*DEFAULT_EXCLUDE_SELECTORS, *exclude_selectors]:
        for node in safe_select(soup, selector, target_id):
            node.decompose()
    for node in list(soup.find_all(True)):
        class_value = " ".join(node.get("class", []))
        id_value = str(node.get("id", ""))
        if NOISE_ATTR_RE.search(f"{class_value} {id_value}"):
            node.decompose()


def apply_ignore_patterns(text: str, patterns: list[str], target_id: str) -> str:
    result = text
    for pattern in patterns:
        try:
            result = re.sub(pattern, " ", result)
        except re.error as exc:
            raise MonitorError(f"Target {target_id} has invalid ignore_patterns") from exc
    return normalize_text(result)


def extract_text_from_node(node: BeautifulSoup | Tag, config: TargetConfig) -> str:
    remove_noise(node, config.exclude_selectors, config.id)
    text = normalize_text(node.get_text(" ", strip=True))
    return apply_ignore_patterns(text, config.ignore_patterns, config.id)


def extract_selected_text(soup: BeautifulSoup, config: TargetConfig) -> str:
    parts: list[str] = []
    for selector in config.selectors:
        parts.extend(extract_text_from_node(node, config) for node in safe_select(soup, selector, config.id))
    return normalize_text(" ".join(parts))


def normalized_url(base_url: str, href: str, strip_params: list[str]) -> str:
    parsed = urlparse(urljoin(base_url, href))
    strip_set = set(strip_params)
    query_items = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key not in strip_set]
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, "", urlencode(query_items), ""))


def field_value(node: Tag, field_name: str, spec: Any, base_url: str, strip_params: list[str], target_id: str) -> str:
    selector = spec if isinstance(spec, str) else spec["selector"]
    selected = node if selector == ":self" else safe_select_one(node, selector, target_id)
    if selected is None:
        return ""
    attr = spec.get("attr") if isinstance(spec, dict) else None
    if attr:
        raw_value = str(selected.get(attr, ""))
    elif field_name == "url" and selected.name == "a":
        href = selected.get("href")
        raw_value = urljoin(base_url, str(href)) if href else ""
    else:
        raw_value = normalize_text(selected.get_text(" ", strip=True))

    if isinstance(spec, dict) and spec.get("regex"):
        try:
            match = re.search(spec["regex"], raw_value)
        except re.error:
            raise MonitorError(f"Target {target_id} has invalid field pattern") from None
        if not match:
            return ""
        group = spec.get("group", 1)
        try:
            raw_value = match.group(group)
        except IndexError:
            raise MonitorError(f"Target {target_id} has invalid field pattern") from None

    if attr == "href" or field_name == "url":
        return normalized_url(base_url, raw_value, strip_params) if raw_value else ""
    return normalize_text(raw_value)


def item_id_for(node: Tag, text: str, config: TargetConfig) -> str:
    if config.item_key_strategy == "link_hash":
        anchor = node if node.name == "a" and node.get("href") else safe_select_one(node, "a[href]", config.id)
        if anchor and anchor.get("href"):
            return sha256_value(normalized_url(config.url, str(anchor["href"]), config.strip_query_params))
    return sha256_value(text)


def item_details(node: Tag, config: TargetConfig) -> dict[str, str]:
    details: dict[str, str] = {"source_id": config.id}
    for name, selector in config.fields.items():
        value = field_value(node, name, selector, config.url, config.strip_query_params, config.id)
        if value:
            details[name] = value
    return details


def build_text_current(html: str, config: TargetConfig) -> tuple[dict[str, Any], list[dict[str, str]]]:
    soup = BeautifulSoup(html, "html.parser")
    mode = config.effective_mode
    text = extract_selected_text(soup, config) if mode == "selected_text" else extract_text_from_node(soup, config)
    return {"content_hash": sha256_value(text)}, []


def build_item_current(html: str, config: TargetConfig) -> tuple[dict[str, Any], list[dict[str, str]]]:
    soup = BeautifulSoup(html, "html.parser")
    remove_noise(soup, config.exclude_selectors, config.id)

    items: dict[str, str] = {}
    details_by_item: dict[str, dict[str, str]] = {}
    for selector in config.item_selectors:
        for original_node in safe_select(soup, selector, config.id):
            node = BeautifulSoup(str(original_node), "html.parser")
            remove_noise(node, [*config.exclude_selectors, *config.item_exclude_selectors], config.id)
            item_node = node.find(True)
            if item_node is None:
                continue
            text = apply_ignore_patterns(normalize_text(item_node.get_text(" ", strip=True)), config.ignore_patterns, config.id)
            if not text:
                continue
            item_id = item_id_for(original_node, text, config)
            items[item_id] = sha256_value(text)
            details_by_item[item_id] = item_details(original_node, config)

    return {"items": dict(sorted(items.items()))}, [{"item_id": key, **value} for key, value in details_by_item.items()]


def build_current(html: str, config: TargetConfig) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if config.effective_mode == "item_list":
        return build_item_current(html, config)
    return build_text_current(html, config)


def roll_history(existing: list[str], new_ids: list[str], max_items: int) -> list[str]:
    if max_items == 0:
        return []
    result = [item for item in existing if item not in new_ids]
    result.extend(new_ids)
    return result[-max_items:]


def build_next_target_state(
    previous: dict[str, Any],
    current: dict[str, Any],
    config: TargetConfig,
    should_update: bool,
) -> dict[str, Any]:
    mode = config.effective_mode
    history = previous.get("history", {})
    if mode == "item_list":
        current_item_ids = list(current.get("items", {}).keys())
        recent = roll_history(history.get("recent_item_ids", []), current_item_ids, config.history_max_items)
        return {"mode": mode, "current": current, "history": {"recent_item_ids": recent}}
    recent_hashes = history.get("recent_content_hashes", [])
    if should_update:
        recent_hashes = roll_history(recent_hashes, [current["content_hash"]], config.history_max_items)
    return {"mode": mode, "current": current, "history": {"recent_content_hashes": recent_hashes}}


def item_diff(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, list[str]]:
    previous_items = previous.get("current", {}).get("items", {})
    current_items = current.get("items", {})
    return {
        "added": sorted(set(current_items) - set(previous_items)),
        "removed": sorted(set(previous_items) - set(current_items)),
        "changed": sorted(item_id for item_id in set(current_items) & set(previous_items) if current_items[item_id] != previous_items[item_id]),
    }


def target_notification(
    config: TargetConfig,
    previous: dict[str, Any],
    current: dict[str, Any],
    details: list[dict[str, str]],
) -> tuple[bool, bool, dict[str, Any] | None]:
    mode = config.effective_mode
    if mode == "item_list":
        diff = item_diff(previous, current)
        counts = {key: len(value) for key, value in diff.items()}
        has_change = any(counts.values())
        notify_events = [event for event in ("added", "removed", "changed") if counts[event] and event in config.effective_notify_on]
        should_notify = bool(notify_events)
        should_update = should_notify or (has_change and config.update_state_on_non_notified_change)
        if not should_notify:
            return has_change, should_update, None

        detail_map = {item["item_id"]: item for item in details}
        changed_ids = [item_id for event in notify_events for item_id in diff[event]]
        total_count = len(changed_ids)
        included_ids = changed_ids[: config.max_notify_items]
        items = []
        for item_id in included_ids:
            item = {key: value for key, value in detail_map.get(item_id, {}).items() if key != "item_id"}
            item["change"] = next(event for event in notify_events if item_id in diff[event])
            items.append(item)
        return has_change, should_update, {
            "source_id": config.id,
            "source_label": config.label,
            "notification_sort_rules": config.notification_sort_rules,
            "mode": mode,
            "counts": counts,
            "truncated": total_count > len(included_ids),
            "included_count": len(included_ids),
            "total_count": total_count,
            "items": items,
        }

    previous_hash = previous.get("current", {}).get("content_hash")
    has_change = previous_hash != current.get("content_hash")
    should_notify = has_change and "any_change" in config.effective_notify_on
    should_update = should_notify or (has_change and config.update_state_on_non_notified_change)
    if not should_notify:
        return has_change, should_update, None
    return has_change, should_update, {
        "source_id": config.id,
        "source_label": config.label,
        "notification_sort_rules": config.notification_sort_rules,
        "mode": mode,
        "counts": {"changed": 1},
        "truncated": False,
        "included_count": 0,
        "total_count": 1,
        "items": [],
    }


def encrypted_dispatch_body(payload: dict[str, Any], fernet: Fernet) -> dict[str, Any]:
    working = json.loads(json.dumps(payload))
    while True:
        ciphertext = encrypt_json(working, fernet)
        body = {"event_type": "notify", "client_payload": {"encrypted": True, "ciphertext": ciphertext}}
        body_size = len(json.dumps(body, separators=(",", ":")).encode("utf-8"))
        if body_size <= DISPATCH_BODY_LIMIT_BYTES:
            return body
        largest = max(
            (target for target in working.get("targets", []) if target.get("items")),
            key=lambda target: len(target.get("items", [])),
            default=None,
        )
        if largest is None:
            raise MonitorError("Encrypted dispatch payload is too large")
        largest["items"].pop()
        largest["included_count"] = len(largest["items"])
        largest["truncated"] = True
        if not largest["items"]:
            raise MonitorError("Encrypted dispatch payload is too large")


def dispatch_notification(payload: dict[str, Any], fernet: Fernet) -> None:
    repo = env_required("DISPATCH_REPO")
    token = env_required("DISPATCH_TOKEN")
    body = encrypted_dispatch_body(payload, fernet)
    response = requests.post(
        f"https://api.github.com/repos/{repo}/dispatches",
        headers=gist_headers(token),
        json=body,
        timeout=TIMEOUT_SECONDS,
    )
    if response.status_code != 204:
        raise MonitorError("Failed to dispatch notification")


def main() -> None:
    configs = load_targets()
    state_fernet = fernet_from_env("STATE_ENCRYPTION_KEY")
    payload_fernet = fernet_from_env("PAYLOAD_ENCRYPTION_KEY")
    state = load_encrypted_state(state_fernet)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    next_state = {"version": 1, "targets": dict(state.get("targets", {}))}
    notification_targets: list[dict[str, Any]] = []
    state_updates = 0

    for config in configs:
        html = fetch_html(session, config)
        current, details = build_current(html, config)
        previous = state.get("targets", {}).get(config.id, {})

        if not previous:
            next_state["targets"][config.id] = build_next_target_state(previous, current, config, True)
            state_updates += 1
            print(f"{config.id}: baseline mode={config.effective_mode}")
            continue

        has_change, should_update, notification = target_notification(config, previous, current, details)
        if notification:
            notification_targets.append(notification)
        if should_update:
            next_state["targets"][config.id] = build_next_target_state(previous, current, config, True)
            state_updates += 1

        status = "changed" if has_change else "no-change"
        print(f"{config.id}: {status} mode={config.effective_mode}")

    if state_updates == 0:
        print("No encrypted state update required")
        return

    if notification_targets:
        dispatch_payload = {
            "version": 1,
            "event_id": str(uuid.uuid4()),
            "detected_at": utc_now(),
            "targets": notification_targets,
        }
        dispatch_notification(dispatch_payload, payload_fernet)
        print(f"Dispatched notification for {len(notification_targets)} target(s)")

    save_encrypted_state(next_state, state_fernet)
    print(f"Saved encrypted state for {state_updates} target(s)")


if __name__ == "__main__":
    try:
        main()
    except MonitorError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
