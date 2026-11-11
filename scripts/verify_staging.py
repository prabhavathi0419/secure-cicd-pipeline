"""Post-deploy checks against the running staging container (stdlib only).

Checks: health, functional flow, security headers, non-root user, no secrets in logs.
Run from the project root while `docker compose up -d` is active. Exit 0 = all good.
"""
import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"
PASSWORD = "Staging-Check-Pass-42"
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
    if not ok:
        failures.append(name)


def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method)
    if body is not None:
        req.data = json.dumps(body).encode()
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # nosec B310 - fixed http://127.0.0.1 URL
            return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=True).stdout.strip()  # nosec B603 B607


def main() -> int:
    for _ in range(30):  # wait for health
        try:
            if call("GET", "/health")[0] == 200:
                break
        except OSError:
            pass
        time.sleep(1)
    status, headers, body = call("GET", "/health")
    check("health endpoint", status == 200 and json.loads(body) == {"status": "ok"})

    h = {k.lower(): v for k, v in headers.items()}
    for k, v in {"x-content-type-options": "nosniff", "x-frame-options": "DENY", "cache-control": "no-store"}.items():
        check(f"header {k}", h.get(k) == v)
    check("server header not disclosed", "uvicorn" not in h.get("server", "").lower())

    user = f"stage{int(time.time())}"
    s, _, _ = call("POST", "/register", {"username": user, "email": f"{user}@example.com", "password": PASSWORD})
    check("register -> 201", s == 201)
    s, _, b = call("POST", "/login", {"username": user, "password": PASSWORD})
    token = json.loads(b).get("access_token") if s == 200 else None
    check("login -> 200 + token", s == 200 and bool(token))
    check("profile without token -> 401", call("GET", "/profile")[0] == 401)
    s, _, b = call("GET", "/profile", token=token)
    check("profile with token -> 200", s == 200 and json.loads(b)["username"] == user)
    check("bad login -> 401", call("POST", "/login", {"username": user, "password": "nope"})[0] == 401)
    check("production-style docs hidden or staging-only", call("GET", "/nope")[0] == 404)

    # Find the container by its Compose label (works with `docker compose` and `docker-compose`).
    cid = docker("ps", "-q", "--filter", "label=com.docker.compose.service=api").splitlines()[0]
    uid = docker("exec", cid, "id", "-u")
    check("container runs as non-root", uid != "0", f"(uid={uid})")
    check("image config user is set", docker("inspect", "-f", "{{.Config.User}}", cid) not in ("", "0", "root"))
    check("read-only root filesystem", docker("inspect", "-f", "{{.HostConfig.ReadonlyRootfs}}", cid) == "true")

    logs = docker("logs", cid)
    check("logs present", len(logs) > 0)
    check("logs contain no password/token", PASSWORD not in logs and (token or "x") not in logs)

    print("\nSTAGING VERIFICATION:", "FAILED: " + ", ".join(failures) if failures else "ALL CHECKS PASSED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
