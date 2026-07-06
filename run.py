"""
Start the DemoCorp dashboard.

This is the only entry point for running the application.

    python run.py

Then open http://127.0.0.1:5000 in your browser.

To regenerate log data first, use:
    python generator/generate.py
"""

import os

from app import SIGNINS_JSON, app


def main() -> None:
    """Start the Flask development server."""
    if not os.path.exists(SIGNINS_JSON):
        print("Warning: No log data found in /data.")
        print("Run this first: python generator/generate.py\n")

    print("Starting DemoCorp dashboard...")
    print("Open http://127.0.0.1:5000 in your browser")
    print("Press Ctrl+C to stop the server\n")

    app.run(debug=True, port=5000, use_reloader=False)


if __name__ == "__main__":
    main()
