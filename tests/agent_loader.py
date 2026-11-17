import importlib.util
import os
import re
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "deploymentovpn.sh"
ENV = {
    "AGENT_API_KEY": "x",
    "SERVER_ID": "s",
    "DASHBOARD_API_URL": "http://localhost",
    "EASY_RSA_INDEX_PATH": "/nonexistent",
}


def load_agent():
    """Extract the agent's Python heredoc from deploymentovpn.sh and import it."""
    text = SCRIPT.read_text()
    m = re.search(r"<< '_PYTHON_SCRIPT_EOF_'[^\n]*\n(.*?)\n_PYTHON_SCRIPT_EOF_\n", text, re.S)
    os.environ.update(ENV)  # set first: load_dotenv() does not override existing env
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "agent_main.py"
        path.write_text(m.group(1) + "\n")
        spec = importlib.util.spec_from_file_location("agent_main", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod
