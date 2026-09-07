"""Drop one real response between the public binary and an external caller."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import threading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    with (args.evidence / "gateway-stderr.txt").open("w") as error:
        process = subprocess.Popen([args.binary, "mcp-stdio", "--config", args.config],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error, text=True, bufsize=1)

        def relay():
            for line in process.stdout:
                value = json.loads(line)
                if value.get("id") == "lost-ack":
                    with (args.evidence / "withheld-response.json").open("x") as output:
                        json.dump(value, output, sort_keys=True)
                else:
                    sys.stdout.write(line)
                    sys.stdout.flush()

        reader = threading.Thread(target=relay, daemon=True)
        reader.start()
        try:
            for line in sys.stdin:
                process.stdin.write(line)
                process.stdin.flush()
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=5)
            reader.join(timeout=5)


if __name__ == "__main__":
    main()
