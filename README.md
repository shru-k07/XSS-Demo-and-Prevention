# XSS Demo and Prevention App

A local Flask classroom project demonstrating reflected/stored XSS concepts and safe output handling. Includes registration, login, logout, SQLite storage, CSRF form tokens, a protected dashboard, and a safe message board.

## Requirements
- Python 3.10 or newer
- Internet connection only to install Flask

## Run on Windows
1. Extract the ZIP.
2. Open the extracted folder in VS Code.
3. Open Terminal in that folder.
4. Create a virtual environment:
   `py -m venv venv`
5. Activate it:
   `venv\Scripts\activate`
6. Install Flask:
   `pip install -r requirements.txt`
7. Start:
   `python app.py`
8. Open `http://127.0.0.1:5000` in your browser.
9. Register an account, log in, and open the XSS Lab.

## Run on macOS / Linux
`python3 -m venv venv`
`source venv/bin/activate`
`pip install -r requirements.txt`
`python app.py`

## Demonstration
In the XSS Lab, try this harmless proof-of-concept string:
`<script>alert('XSS demo')</script>`

- Safe preview: the text is shown as text because Jinja auto-escapes template variables.
- Vulnerable demo: the deliberately unsafe page inserts the submitted value as raw HTML, so the browser may execute the alert. Use only on your own local lab.
- The message board is safe: submitted messages are rendered with Jinja auto-escaping.

## Project structure
- `app.py` – Flask routes, authentication, SQLite, CSRF token check
- `templates/` – HTML pages
- `static/style.css` – styling
- `xss_lab.db` – created automatically on first run

## Important security note
The vulnerable route exists only to teach the risk. Do not deploy this project publicly. In real applications, never mark untrusted input as safe and never render it as raw HTML. Keep template auto-escaping enabled, validate input, use secure session settings and HTTPS, and replace the development secret key before deployment.
