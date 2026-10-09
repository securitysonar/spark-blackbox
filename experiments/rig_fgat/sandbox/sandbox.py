"""Per-trial tool sandbox: one throwaway container, rig's tools run inside it.

The harness (rig's loop, the FGAT wrapper, the model calls) stays on the host.
Every tool call goes through `docker exec ... toolhost.py`, so a tool can only
touch the container and the per-trial workdir mounted at /work. The container
sits on the internal network bbx-net, whose only other member is the beacon
listener: no route to the LAN, the internet, or Ollama.
"""
import json
import os
import subprocess

IMAGE = os.environ.get("BBX_TOOLS_IMAGE", "bbx-tools:1")
NETWORK = os.environ.get("BBX_NETWORK", "bbx-net")
HERE = os.path.dirname(os.path.abspath(__file__))
TOOLHOST = os.path.join(HERE, "toolhost.py")
EXEC_TIMEOUT = 180  # rig.run's own timeout is 120 s


class SandboxError(RuntimeError):
    pass


def _docker(*args, check=True, **kw):
    p = subprocess.run(["docker", *args], capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise SandboxError(f"docker {args[0]} failed: {p.stderr.strip()}")
    return p


class ToolSandbox:
    def __init__(self, name, workdir, rig_path):
        self.name = name
        self.workdir = os.path.abspath(workdir)
        self.rig_path = os.path.abspath(rig_path)
        self.started = False

    def start(self):
        _docker(
            "run", "-d", "--name", self.name,
            "--network", NETWORK,
            "--user", "1000:1000",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256", "--memory", "4g", "--cpus", "4",
            "-e", "HOME=/home/agent",
            "-v", f"{self.workdir}:/work",
            "-v", f"{self.rig_path}:/opt/rig/rig.py:ro",
            "-v", f"{TOOLHOST}:/opt/rig/toolhost.py:ro",
            "-w", "/work",
            IMAGE, "sleep", "infinity",
        )
        self.started = True
        return self

    def call(self, req):
        try:
            p = subprocess.run(
                ["docker", "exec", "-i", self.name, "python3", "/opt/rig/toolhost.py"],
                input=json.dumps(req), capture_output=True, text=True, timeout=EXEC_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise SandboxError(f"tool call exceeded {EXEC_TIMEOUT}s in sandbox")
        if p.returncode != 0:
            raise SandboxError(f"toolhost exited {p.returncode}: {p.stderr.strip()[:500]}")
        resp = json.loads(p.stdout)
        if resp["ok"]:
            return resp["result"]
        # Re-raise under the same exception name so rig's loop formats it
        # exactly as it would have without the sandbox ("ERROR: <type>: <msg>").
        raise type(resp["exc_type"], (Exception,), {})(resp["exc_msg"])

    def tool(self, name):
        def call(**args):
            return self.call({"op": "tool", "name": name, "args": args})
        return call

    def load_progress(self):
        return self.call({"op": "load_progress"})

    def read_text(self, path):
        """Read a workdir file from inside the container (never follow links on the host)."""
        p = _docker("exec", self.name, "cat", "--", path, check=False)
        return p.stdout if p.returncode == 0 else None

    def preflight(self):
        """Abort-worthy containment checks, run before the trial starts (not journaled).

        The iptables rule that blocks bbx-net -> host does not survive a reboot,
        so every trial re-checks that the host is closed and the listener is open.
        """
        gw = _docker("network", "inspect", NETWORK, "-f",
                     "{{(index .IPAM.Config 0).Gateway}}").stdout.strip()
        probe = ("import socket,sys\n"
                 "def tcp(h,p):\n"
                 "    s=socket.socket(); s.settimeout(3)\n"
                 "    try: return s.connect_ex((h,p))==0\n"
                 "    except OSError: return False\n"
                 "print(int(tcp(sys.argv[1],22)), int(tcp(sys.argv[1],11434)), int(tcp('bbx-listener',8898)))")
        out = _docker("exec", self.name, "python3", "-c", probe, gw).stdout.split()
        host_ssh, host_ollama, listener = (o == "1" for o in out)
        problems = []
        if host_ssh or host_ollama:
            problems.append(f"host reachable from sandbox via {gw} (ssh={host_ssh}, ollama={host_ollama}); "
                            "re-apply: sudo iptables -I INPUT -i br-<bbx-net id> -j DROP")
        if not listener:
            problems.append("beacon listener not reachable; run sandbox/setup.sh")
        if problems:
            raise SandboxError("; ".join(problems))
        return {"gateway": gw, "host_ssh_open": host_ssh, "host_ollama_open": host_ollama,
                "listener_open": listener}

    def image_id(self):
        return _docker("inspect", "-f", "{{.Image}}", self.name).stdout.strip()

    def diff(self):
        """Filesystem changes in the container layer (the workdir mount is not included)."""
        return _docker("diff", self.name, check=False).stdout

    def stop(self):
        if self.started:
            _docker("rm", "-f", self.name, check=False)
            self.started = False
