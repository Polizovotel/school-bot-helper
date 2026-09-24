#!/usr/bin/env python3
"""
Дашборд для просмотра трафика, проходящего через VPN (Xray access log).
Показывает: время, IP клиента, домен назначения, порт.

Запуск (для теста):
    DASHBOARD_PASSWORD=мойпароль python3 traffic_dashboard.py

В продакшене запускается как systemd-сервис (см. инструкцию).
"""

import os
import re
import json
from collections import deque
from functools import wraps

from flask import Flask, request, Response, jsonify, render_template_string

# --- НАСТРОЙКИ ---
LOG_PATH = os.getenv("XRAY_LOG_PATH", "/var/log/x-ui/access.log")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD")
MAX_ENTRIES = 2000  # сколько последних записей держим в памяти

if not DASHBOARD_PASSWORD:
    raise RuntimeError(
        "Не задан DASHBOARD_PASSWORD. Установите переменную окружения перед запуском."
    )

app = Flask(__name__)

# Типичная строка лога Xray:
# 2026/09/24 15:32:10 [Info] from 5.44.12.31:51022 accepted tcp:instagram.com:443 [main -> direct]
LOG_LINE_RE = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\[[^\]]*\]\s+from\s+(?P<ip>[\d.]+):\d+\s+accepted\s+"
    r"(?P<proto>tcp|udp):(?P<dest>[^\s:]+):(?P<port>\d+)"
)


def parse_log() -> list:
    """Читает файл лога и возвращает список записей (последние MAX_ENTRIES)."""
    if not os.path.exists(LOG_PATH):
        return []

    entries = deque(maxlen=MAX_ENTRIES)
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = LOG_LINE_RE.match(line)
                if not m:
                    continue
                entries.append({
                    "date": m.group("date"),
                    "time": m.group("time"),
                    "ip": m.group("ip"),
                    "dest": m.group("dest"),
                    "port": m.group("port"),
                    "proto": m.group("proto"),
                })
    except Exception as e:
        app.logger.error(f"Ошибка чтения лога: {e}")
        return []

    return list(entries)[::-1]  # новые сверху


def check_auth(password: str) -> bool:
    return password == DASHBOARD_PASSWORD


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.password):
            return Response(
                "Требуется авторизация.", 401,
                {"WWW-Authenticate": 'Basic realm="VPN Traffic Dashboard"'}
            )
        return f(*args, **kwargs)
    return decorated


PAGE_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN — журнал соединений</title>
<style>
  :root {
    --bg: #0b0f0e;
    --panel: #111715;
    --line: #1e2825;
    --text: #d9e6e0;
    --muted: #6f8880;
    --accent: #4fd1a5;
    --accent-dim: #2c6b52;
    --mono: "SF Mono", "JetBrains Mono", Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    font-size: 14px;
    padding: 24px;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--line);
    padding-bottom: 14px;
  }
  h1 {
    font-size: 16px;
    font-weight: 600;
    letter-spacing: 0.02em;
    margin: 0;
    color: var(--accent);
  }
  #stats { color: var(--muted); font-size: 12px; }
  #search {
    width: 100%;
    max-width: 340px;
    background: var(--panel);
    border: 1px solid var(--line);
    color: var(--text);
    padding: 8px 10px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 13px;
    margin-bottom: 14px;
  }
  #search:focus { outline: none; border-color: var(--accent-dim); }
  table { width: 100%; border-collapse: collapse; }
  th {
    text-align: left;
    color: var(--muted);
    font-weight: 500;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 8px 10px;
    border-bottom: 1px solid var(--line);
  }
  td {
    padding: 7px 10px;
    border-bottom: 1px solid var(--line);
    white-space: nowrap;
  }
  tr:hover td { background: var(--panel); }
  .dest { color: var(--accent); font-weight: 500; }
  .ip { color: var(--muted); }
  .empty { color: var(--muted); padding: 30px 10px; text-align: center; }
</style>
</head>
<body>
  <header>
    <h1>VPN — журнал соединений</h1>
    <div id="stats">—</div>
  </header>
  <input id="search" type="text" placeholder="Фильтр по домену или IP...">
  <table>
    <thead>
      <tr><th>Время</th><th>IP</th><th>Домен</th><th>Порт</th><th>Протокол</th></tr>
    </thead>
    <tbody id="rows"><tr><td class="empty" colspan="5">Загрузка...</td></tr></tbody>
  </table>

<script>
let allEntries = [];

async function fetchData() {
  try {
    const res = await fetch('/api/entries', { credentials: 'include' });
    if (!res.ok) return;
    allEntries = await res.json();
    render();
  } catch (e) { console.error(e); }
}

function render() {
  const q = document.getElementById('search').value.trim().toLowerCase();
  const filtered = q
    ? allEntries.filter(e => e.dest.toLowerCase().includes(q) || e.ip.includes(q))
    : allEntries;

  document.getElementById('stats').textContent =
    filtered.length + ' записей' + (q ? ' (из ' + allEntries.length + ')' : '');

  const tbody = document.getElementById('rows');
  if (filtered.length === 0) {
    tbody.innerHTML = '<tr><td class="empty" colspan="5">Ничего не найдено.</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.slice(0, 500).map(e => `
    <tr>
      <td>${e.date} ${e.time}</td>
      <td class="ip">${e.ip}</td>
      <td class="dest">${e.dest}</td>
      <td>${e.port}</td>
      <td>${e.proto}</td>
    </tr>
  `).join('');
}

document.getElementById('search').addEventListener('input', render);
fetchData();
setInterval(fetchData, 5000);
</script>
</body>
</html>
"""


@app.route("/")
@requires_auth
def index():
    return render_template_string(PAGE_TEMPLATE)


@app.route("/api/entries")
@requires_auth
def api_entries():
    return jsonify(parse_log())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8090)
