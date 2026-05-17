from vercel_wsgi import handle_wsgi_app
from app import app as application

# Create a WSGI handler for Vercel that uses the Flask `app` from root app.py
app_handler = handle_wsgi_app(application)

def handler(request, response):
    return app_handler(request, response)
