"""
WSGI entry point for mod_wsgi on silk.
Apache config example (in .htaccess or httpd conf):

    WSGIScriptAlias / /home/jcalford/public_html/hello_auth/wsgi.py
    WSGIDaemonProcess hello_auth python-home=/home/jcalford/venv threads=5
    WSGIProcessGroup hello_auth
"""
import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, os.path.dirname(__file__))

# Load .env if present (dev only — silk uses real env vars)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except ImportError:
    pass

from app import app as application
