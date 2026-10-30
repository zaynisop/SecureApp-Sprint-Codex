"""SecureApp-Sprint-Codex — development entry point.

Run:  python run.py
The production app is SECURE by default. Deliberately vulnerable
proof-of-concept code lives only under vulnerable_demo/ and is NEVER
imported by the running application.
"""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # debug=False: never expose the Werkzeug debugger (RCE risk) in demos.
    app.run(host="127.0.0.1", port=5000, debug=False)
