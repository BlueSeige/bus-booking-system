# app.py — Single-file Staff Bus Booking App (SQLite: db.db)
# Run:  python app.py
# Requires: pip install flask flask-login flask-sqlalchemy passlib[bcrypt]

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from passlib.hash import bcrypt
from datetime import datetime, date, time, timedelta
import os, random, string, csv
from sqlalchemy.exc import IntegrityError

APP_SECRET = "change-this-secret"
DB_PATH = "sqlite:///db.db"  # <-- uses db.db in project root
CANCEL_CUTOFF_MINUTES = 30     # default; can be updated via admin settings

app = Flask(__name__)
app.config.update(
    SECRET_KEY=APP_SECRET,
    SQLALCHEMY_DATABASE_URI=DB_PATH,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -------------------- MODELS --------------------
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="staff")  # 'staff', 'admin', 'verifier'

    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)

class Bus(db.Model):
    __tablename__ = "buses"
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(120))  # optional route or label

    bookings = db.relationship("Booking", back_populates="bus", cascade="all,delete-orphan")

    @property
    def seats_taken(self):
        return sum(1 for b in self.bookings if b.status in ("confirmed", "checked_in"))

    @property
    def seats_left(self):
        return max(self.capacity - self.seats_taken, 0)

    def departure_dt(self):
        return datetime.combine(self.date, self.time)

class Booking(db.Model):
    __tablename__ = "bookings"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    bus_id = db.Column(db.Integer, db.ForeignKey("buses.id"), nullable=False)
    status = db.Column(db.String(20), default="confirmed")  # confirmed | cancelled | checked_in
    code = db.Column(db.String(20), unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="bookings")
    bus = db.relationship("Bus", back_populates="bookings")

    __table_args__ = (
        db.UniqueConstraint("user_id", "bus_id", name="uq_user_bus_once"),
    )

# -------------------- HELPERS --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def verifier_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in ("verifier", "admin"):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# -------------------- AUTH --------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name").strip()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        if User.query.filter_by(email=email).first():
            flash("Email already registered", "warning")
            return redirect(url_for("register"))
        u = User(name=name, email=email, role="staff")
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    # Placeholder UI; implement email flow later if needed
    if request.method == "POST":
        flash("If this email exists, a reset link will be sent.", "info")
        return redirect(url_for("login"))
    return render_template("forgot.html")

# -------------------- USER PAGES --------------------
@app.route("/")
@login_required
def dashboard():
    buses = Bus.query.filter(Bus.date >= date.today()).order_by(Bus.date, Bus.time).all()
    return render_template("dashboard.html", buses=buses, cutoff=CANCEL_CUTOFF_MINUTES)

@app.route("/buses")
@login_required
def buses_list():
    qdate = request.args.get("date")
    qry = Bus.query
    if qdate:
        try:
            d = datetime.strptime(qdate, "%Y-%m-%d").date()
            qry = qry.filter(Bus.date == d)
        except ValueError:
            pass
    else:
        qry = qry.filter(Bus.date >= date.today())
    buses = qry.order_by(Bus.date, Bus.time).all()
    return render_template("buses.html", buses=buses)

@app.route("/buses/<int:bus_id>")
@login_required
def bus_detail(bus_id):
    bus = Bus.query.get_or_404(bus_id)
    booking = None
    if current_user.is_authenticated:
        booking = Booking.query.filter_by(bus_id=bus.id, user_id=current_user.id).filter(Booking.status != "cancelled").first()
    return render_template("bus_detail.html", bus=bus, booking=booking)

@app.route("/book/<int:bus_id>", methods=["POST"])
@login_required
def book(bus_id):
    bus = Bus.query.get_or_404(bus_id)

    # capacity check
    if bus.seats_left <= 0:
        flash("No seats left", "danger")
        return redirect(url_for("bus_detail", bus_id=bus.id))

    # prevent double booking (active bookings only)
    existing_active = (
        Booking.query
        .filter_by(bus_id=bus.id, user_id=current_user.id)
        .filter(Booking.status != "cancelled")
        .first()
    )
    if existing_active:
        flash("You already have a booking for this bus", "warning")
        return redirect(url_for("bus_detail", bus_id=bus.id))

    # look for a previous cancelled booking
    previous = (
        Booking.query
        .filter_by(bus_id=bus.id, user_id=current_user.id, status="cancelled")
        .order_by(Booking.created_at.desc())
        .first()
    )

    if previous:
        # REBOOK: update cancelled booking instead of inserting new one
        previous.status = "confirmed"
        previous.created_at = datetime.utcnow()
        booking = previous
        db.session.add(previous)
    else:
        # FIRST-TIME BOOKING: generate unique code
        code = "BK" + ''.join(random.choices(string.digits, k=8))
        while Booking.query.filter_by(code=code).first():
            code = "BK" + ''.join(random.choices(string.digits, k=8))

        booking = Booking(
            user_id=current_user.id,
            bus_id=bus.id,
            code=code,
            status="confirmed",
            created_at=datetime.utcnow()
        )
        db.session.add(booking)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash("Booking failed due to a database constraint. Please try again.", "danger")
        return redirect(url_for("bus_detail", bus_id=bus.id))

    flash("Seat booked!", "success")
    return redirect(url_for("booking_detail", booking_id=booking.id))


@app.route("/booking/<int:booking_id>")
@login_required
def booking_detail(booking_id):
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != current_user.id and current_user.role not in ("admin", "verifier"):
        abort(403)
    return render_template("booking_detail.html", b=b)

@app.route("/booking/<int:booking_id>/cancel", methods=["POST"]) 
@login_required
def booking_cancel(booking_id):
    b = Booking.query.get_or_404(booking_id)
    if b.user_id != current_user.id and current_user.role != "admin":
        abort(403)
    # enforce cancellation cutoff
    depart = b.bus.departure_dt()
    if depart - datetime.now() <= timedelta(minutes=CANCEL_CUTOFF_MINUTES):
        flash(f"Cannot cancel within {CANCEL_CUTOFF_MINUTES} minutes of departure.", "warning")
        return redirect(url_for("my_bookings"))
    b.status = "cancelled"
    db.session.commit()
    flash("Booking cancelled", "info")
    return redirect(url_for("my_bookings"))

@app.route("/my-bookings")
@login_required
def my_bookings():
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.created_at.desc()).all()
    return render_template("my_bookings.html", bookings=bookings)

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

# -------------------- VERIFIER / CONDUCTOR --------------------
@app.route("/verify", methods=["GET", "POST"]) 
@login_required
@verifier_required
def verify():
    booking = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        booking = Booking.query.filter_by(code=code).first()
        if not booking or booking.status == "cancelled":
            flash("Invalid or cancelled booking", "danger")
        else:
            flash("Valid booking", "success")
    return render_template("verify.html", booking=booking)

@app.route("/manifest/<int:bus_id>", methods=["GET", "POST"]) 
@login_required
@verifier_required
def manifest(bus_id):
    bus = Bus.query.get_or_404(bus_id)
    # optional: mark check-in
    if request.method == "POST":
        booking_id = request.form.get("booking_id")
        b = Booking.query.get(int(booking_id))
        if b and b.bus_id == bus.id and b.status in ("confirmed", "checked_in"):
            b.status = "checked_in"
            db.session.commit()
            flash("Checked in", "success")
        return redirect(url_for("manifest", bus_id=bus.id))
    bookings = Booking.query.filter_by(bus_id=bus.id).filter(Booking.status != "cancelled").all()
    return render_template("manifest.html", bus=bus, bookings=bookings)

# -------------------- ADMIN --------------------
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    today = date.today()
    todays_buses = Bus.query.filter(Bus.date == today).order_by(Bus.time).all()
    total_bookings = Booking.query.count()
    return render_template("admin/index.html", todays_buses=todays_buses, total_bookings=total_bookings)

@app.route("/admin/buses")
@login_required
@admin_required
def admin_buses():
    buses = Bus.query.order_by(Bus.date.desc(), Bus.time.desc()).all()
    return render_template("admin/buses.html", buses=buses)

@app.route("/admin/buses/new", methods=["GET", "POST"]) 
@login_required
@admin_required
def admin_bus_new():
    if request.method == "POST":
        date_str = request.form.get("date")
        time_str = request.form.get("time")
        capacity = int(request.form.get("capacity"))
        name = request.form.get("name") or None
        d = datetime.strptime(date_str, "%Y-%m-%d").date()
        t = datetime.strptime(time_str, "%H:%M").time()
        db.session.add(Bus(date=d, time=t, capacity=capacity, name=name))
        db.session.commit()
        flash("Bus created", "success")
        return redirect(url_for("admin_buses"))
    return render_template("admin/bus_form.html", bus=None)

@app.route("/admin/buses/<int:bus_id>/edit", methods=["GET", "POST"]) 
@login_required
@admin_required
def admin_bus_edit(bus_id):
    bus = Bus.query.get_or_404(bus_id)
    if request.method == "POST":
        bus.date = datetime.strptime(request.form.get("date"), "%Y-%m-%d").date()
        bus.time = datetime.strptime(request.form.get("time"), "%H:%M").time()
        bus.capacity = int(request.form.get("capacity"))
        bus.name = request.form.get("name") or None
        db.session.commit()
        flash("Bus updated", "success")
        return redirect(url_for("admin_buses"))
    return render_template("admin/bus_form.html", bus=bus)

@app.route("/admin/bookings")
@login_required
@admin_required
def admin_bookings():
    bookings = Booking.query.order_by(Booking.created_at.desc()).all()
    return render_template("admin/bookings.html", bookings=bookings)

@app.route("/admin/users", methods=["GET", "POST"]) 
@login_required
@admin_required
def admin_users():
    if request.method == "POST":
        name = request.form.get("name").strip()
        email = request.form.get("email").strip().lower()
        role = request.form.get("role")
        password = request.form.get("password")
        if User.query.filter_by(email=email).first():
            flash("Email exists", "warning")
        else:
            u = User(name=name, email=email, role=role)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("User created", "success")
        return redirect(url_for("admin_users"))
    users = User.query.order_by(User.id.desc()).all()
    return render_template("admin/users.html", users=users)

@app.route("/admin/reports.csv")
@login_required
@admin_required
def admin_reports_csv():
    # simple CSV: booking_id, user, email, bus_date, bus_time, status
    path = "report.csv"
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["booking_id", "user", "email", "bus_date", "bus_time", "status"]) 
        for b in Booking.query.order_by(Booking.created_at.desc()).all():
            w.writerow([b.id, b.user.name, b.user.email, b.bus.date.isoformat(), b.bus.time.strftime("%H:%M"), b.status])
    return send_file(path, as_attachment=True, download_name="reports.csv")

@app.route("/admin/settings", methods=["GET", "POST"]) 
@login_required
@admin_required
def admin_settings():
    global CANCEL_CUTOFF_MINUTES
    if request.method == "POST":
        try:
            CANCEL_CUTOFF_MINUTES = max(0, int(request.form.get("cutoff")))
            flash("Settings updated", "success")
        except Exception:
            flash("Invalid cutoff", "danger")
        return redirect(url_for("admin_settings"))
    return render_template("admin/settings.html", cutoff=CANCEL_CUTOFF_MINUTES)

# -------------------- API (AJAX) --------------------
@app.route("/api/bus/<int:bus_id>/seats")
@login_required
def api_bus_seats(bus_id):
    bus = Bus.query.get_or_404(bus_id)
    return jsonify({"capacity": bus.capacity, "taken": bus.seats_taken, "left": bus.seats_left})

# -------------------- ERRORS --------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403

@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404

# -------------------- DEV BOOTSTRAP TEMPLATES --------------------
# Create minimal templates on first run so the app renders out of the box.
BASE = """<!doctype html><html><head>
<meta name=viewport content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<title>{% block title %}Staff Bus Booking{% endblock %}</title>
</head><body class="bg-light">
<nav class="navbar navbar-expand-lg navbar-dark bg-dark"><div class="container"><a class="navbar-brand" href="/">SBB</a>
<div class="d-flex">
  {% if current_user.is_authenticated %}
    <a class="btn btn-sm btn-outline-light me-2" href="/profile">{{ current_user.name }}</a>
    {% if current_user.role in ['admin','verifier'] %}<a class="btn btn-sm btn-warning me-2" href="/admin">Admin</a>{% endif %}
    <a class="btn btn-sm btn-danger" href="/logout">Logout</a>
  {% else %}
    <a class="btn btn-sm btn-outline-light" href="/login">Login</a>
  {% endif %}
</div></div></nav>
<main class="container py-4">
{% with messages = get_flashed_messages(with_categories=true) %}
  {% for c,m in messages %}<div class="alert alert-{{c}}">{{m}}</div>{% endfor %}
{% endwith %}
{% block content %}{% endblock %}
</main></body></html>"""

TPLS = {
"login.html": """{% extends 'base.html' %}{% block title %}Login{% endblock %}{% block content %}
<div class='row justify-content-center'><div class='col-md-4'>
<form method=post class='card p-4'>
<h4 class='mb-3'>Login</h4>
<input class='form-control mb-2' name=email type=email placeholder='Email' required>
<input class='form-control mb-3' name=password type=password placeholder='Password' required>
<button class='btn btn-primary w-100'>Login</button>
<div class='text-center mt-3'><a href='/register'>Register</a> · <a href='/forgot-password'>Forgot?</a></div>
</form></div></div>{% endblock %}""",

"register.html": """{% extends 'base.html' %}{% block title %}Register{% endblock %}{% block content %}
<div class='row justify-content-center'><div class='col-md-5'>
<form method=post class='card p-4'>
<h4>Create Account</h4>
<input class='form-control mb-2' name=name placeholder='Full name' required>
<input class='form-control mb-2' name=email type=email placeholder='Email' required>
<input class='form-control mb-3' name=password type=password placeholder='Password' required>
<button class='btn btn-success w-100'>Create</button>
</form></div></div>{% endblock %}""",

"forgot.html": """{% extends 'base.html' %}{% block title %}Forgot Password{% endblock %}{% block content %}
<form method=post class='card p-4 mx-auto' style='max-width:420px'>
<p>Enter your account email. We'll send a reset link if it exists.</p>
<input class='form-control mb-3' type=email name=email placeholder='Email'>
<button class='btn btn-primary w-100'>Send</button>
</form>{% endblock %}""",

"dashboard.html": """{% extends 'base.html' %}{% block title %}Dashboard{% endblock %}{% block content %}
<h3>Upcoming Buses</h3>
<table class='table table-striped'><thead><tr><th>Date</th><th>Time</th><th>Capacity</th><th>Left</th><th></th></tr></thead><tbody>
{% for bus in buses %}
<tr><td>{{ bus.date }}</td><td>{{ '%02d:%02d'|format(bus.time.hour, bus.time.minute) }}</td><td>{{ bus.capacity }}</td><td>{{ bus.seats_left }}</td>
<td><a class='btn btn-sm btn-outline-primary' href='/buses/{{bus.id}}'>View</a></td></tr>
{% endfor %}
</tbody></table>
<p class='text-muted'>Cancellation cutoff: {{ cutoff }} minutes before departure.</p>
{% endblock %}""",

"buses.html": """{% extends 'base.html' %}{% block title %}Buses{% endblock %}{% block content %}
<form class='row g-2 mb-3'>
<div class='col-auto'><input class='form-control' type=date name=date value='{{ request.args.get('date','') }}'></div>
<div class='col-auto'><button class='btn btn-secondary'>Filter</button></div>
</form>
<table class='table table-hover'><thead><tr><th>Date</th><th>Time</th><th>Capacity</th><th>Left</th><th></th></tr></thead><tbody>
{% for bus in buses %}
<tr><td>{{ bus.date }}</td><td>{{ '%02d:%02d'|format(bus.time.hour, bus.time.minute) }}</td><td>{{ bus.capacity }}</td><td>{{ bus.seats_left }}</td>
<td><a class='btn btn-sm btn-outline-primary' href='/buses/{{bus.id}}'>View</a></td></tr>
{% endfor %}
</tbody></table>
{% endblock %}""",

"bus_detail.html": """{% extends 'base.html' %}{% block title %}Bus Detail{% endblock %}{% block content %}
<h3>Bus on {{ bus.date }} at {{ '%02d:%02d'|format(bus.time.hour, bus.time.minute) }}</h3>
<p>Capacity: <b>{{ bus.capacity }}</b> · Seats left: <b id='left'>{{ bus.seats_left }}</b></p>
<form method=post action='/book/{{bus.id}}'>
<button class='btn btn-primary' {% if bus.seats_left==0 %}disabled{% endif %}>Book seat</button>
</form>
<script>
async function refresh(){
  const r = await fetch('/api/bus/{{bus.id}}/seats');
  const d = await r.json();
  document.getElementById('left').innerText = d.left;
}
setInterval(refresh, 5000);
</script>
{% endblock %}""",

"booking_detail.html": """{% extends 'base.html' %}{% block title %}Booking{% endblock %}{% block content %}
<h3>Booking #{{ b.id }}</h3>
<p>Code: <b>{{ b.code }}</b></p>
<p>Bus: {{ b.bus.date }} at {{ '%02d:%02d'|format(b.bus.time.hour, b.bus.time.minute) }}</p>
<p>Status: <span class='badge bg-info text-dark'>{{ b.status }}</span></p>
<form method=post action='/booking/{{ b.id }}/cancel'>
<button class='btn btn-outline-danger'>Cancel Booking</button>
</form>
{% endblock %}""",

"my_bookings.html": """{% extends 'base.html' %}{% block title %}My Bookings{% endblock %}{% block content %}
<h3>My Bookings</h3>
<table class='table table-striped'><thead><tr><th>ID</th><th>Code</th><th>Date</th><th>Time</th><th>Status</th><th></th></tr></thead><tbody>
{% for b in bookings %}
<tr><td>{{ b.id }}</td><td>{{ b.code }}</td><td>{{ b.bus.date }}</td><td>{{ '%02d:%02d'|format(b.bus.time.hour, b.bus.time.minute) }}</td><td>{{ b.status }}</td>
<td><a class='btn btn-sm btn-outline-primary' href='/booking/{{b.id}}'>Open</a></td></tr>
{% endfor %}
</tbody></table>
{% endblock %}""",

"verify.html": """{% extends 'base.html' %}{% block title %}Verify{% endblock %}{% block content %}
<h3>Verify Booking</h3>
<form method=post class='row g-2'>
  <div class='col-auto'><input name=code class='form-control' placeholder='Enter code'></div>
  <div class='col-auto'><button class='btn btn-primary'>Check</button></div>
</form>
{% if booking %}
<div class='alert alert-info mt-3'>
  Booking #{{ booking.id }} — {{ booking.user.name }} · {{ booking.bus.date }} {{ '%02d:%02d'|format(booking.bus.time.hour, booking.bus.time.minute) }} — Status: {{ booking.status }}
</div>
{% endif %}
{% endblock %}""",

"manifest.html": """{% extends 'base.html' %}{% block title %}Manifest{% endblock %}{% block content %}
<h3>Manifest for {{ bus.date }} {{ '%02d:%02d'|format(bus.time.hour, bus.time.minute) }} {% if bus.name %}— {{ bus.name }}{% endif %}</h3>
<table class='table table-hover'><thead><tr><th>ID</th><th>Passenger</th><th>Code</th><th>Status</th><th>Action</th></tr></thead><tbody>
{% for b in bookings %}
<tr><td>{{ b.id }}</td><td>{{ b.user.name }}</td><td>{{ b.code }}</td><td>{{ b.status }}</td>
<td>{% if b.status != 'checked_in' %}
<form method=post>
  <input type=hidden name=booking_id value='{{ b.id }}'>
  <button class='btn btn-sm btn-success'>Mark Checked-in</button>
</form>
{% else %}<span class='text-success'>On board</span>{% endif %}</td></tr>
{% endfor %}
</tbody></table>
{% endblock %}""",

"admin/index.html": """{% extends 'base.html' %}{% block title %}Admin{% endblock %}{% block content %}
<h3>Admin Dashboard</h3>
<p>Total bookings: <b>{{ total_bookings }}</b></p>
<h5>Today's Buses</h5>
<ul>
{% for b in todays_buses %}<li>{{ b.time.strftime('%H:%M') }} — {{ b.name or 'Bus' }} ({{ b.seats_taken }}/{{ b.capacity }}) <a href='/manifest/{{ b.id }}'>Manifest</a></li>{% else %}<li>No buses today</li>{% endfor %}
</ul>
<div class='mt-3'>
  <a class='btn btn-primary' href='/admin/buses'>Manage Buses</a>
  <a class='btn btn-secondary' href='/admin/bookings'>All Bookings</a>
  <a class='btn btn-outline-success' href='/admin/users'>Users</a>
  <a class='btn btn-outline-dark' href='/admin/settings'>Settings</a>
  <a class='btn btn-outline-info' href='/admin/reports.csv'>Export CSV</a>
</div>
{% endblock %}""",

"admin/buses.html": """{% extends 'base.html' %}{% block title %}Admin Buses{% endblock %}{% block content %}
<h3>Buses</h3>
<a class='btn btn-primary mb-3' href='/admin/buses/new'>New Bus</a>
<table class='table table-striped'><thead><tr><th>Date</th><th>Time</th><th>Name</th><th>Capacity</th><th>Taken</th><th></th></tr></thead><tbody>
{% for b in buses %}
<tr><td>{{ b.date }}</td><td>{{ b.time.strftime('%H:%M') }}</td><td>{{ b.name or '' }}</td><td>{{ b.capacity }}</td><td>{{ b.seats_taken }}</td>
<td><a class='btn btn-sm btn-outline-primary' href='/admin/buses/{{b.id}}/edit'>Edit</a> · <a class='btn btn-sm btn-outline-secondary' href='/manifest/{{b.id}}'>Manifest</a></td></tr>
{% endfor %}
</tbody></table>
{% endblock %}""",

"admin/bus_form.html": """{% extends 'base.html' %}{% block title %}Bus Form{% endblock %}{% block content %}
<h3>{{ 'Edit Bus' if bus else 'New Bus' }}</h3>
<form method=post class='card p-4'>
  <div class='row g-3'>
    <div class='col-md-4'><label>Date</label><input type=date name=date class='form-control' value='{{ bus.date if bus else '' }}' required></div>
    <div class='col-md-3'><label>Time</label><input type=time name=time class='form-control' value='{{ bus.time.strftime('%H:%M') if bus else '' }}' required></div>
    <div class='col-md-3'><label>Capacity</label><input type=number name=capacity class='form-control' value='{{ bus.capacity if bus else 20 }}' min=1 required></div>
    <div class='col-md-6'><label>Name (optional)</label><input name=name class='form-control' value='{{ bus.name if bus else '' }}'></div>
  </div>
  <button class='btn btn-primary mt-3'>Save</button>
</form>
{% endblock %}""",

"admin/bookings.html": """{% extends 'base.html' %}{% block title %}All Bookings{% endblock %}{% block content %}
<h3>All Bookings</h3>
<table class='table table-striped'><thead><tr><th>ID</th><th>User</th><th>Email</th><th>Date</th><th>Time</th><th>Status</th></tr></thead><tbody>
{% for b in bookings %}
<tr><td>{{ b.id }}</td><td>{{ b.user.name }}</td><td>{{ b.user.email }}</td><td>{{ b.bus.date }}</td><td>{{ b.bus.time.strftime('%H:%M') }}</td><td>{{ b.status }}</td></tr>
{% endfor %}
</tbody></table>
{% endblock %}""",

"admin/users.html": """{% extends 'base.html' %}{% block title %}Users{% endblock %}{% block content %}
<h3>Users</h3>
<form method=post class='card p-3 mb-3'>
  <div class='row g-2'>
    <div class='col-md-3'><input class='form-control' name=name placeholder='Name' required></div>
    <div class='col-md-3'><input class='form-control' type=email name=email placeholder='Email' required></div>
    <div class='col-md-2'><select class='form-select' name=role><option>staff</option><option>verifier</option><option>admin</option></select></div>
    <div class='col-md-2'><input class='form-control' type=password name=password placeholder='Password' required></div>
    <div class='col-md-2'><button class='btn btn-primary w-100'>Add</button></div>
  </div>
</form>
<table class='table table-striped'><thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th></tr></thead><tbody>
{% for u in users %}<tr><td>{{ u.id }}</td><td>{{ u.name }}</td><td>{{ u.email }}</td><td>{{ u.role }}</td></tr>{% endfor %}
</tbody></table>
{% endblock %}""",

"admin/settings.html": """{% extends 'base.html' %}{% block title %}Settings{% endblock %}{% block content %}
<h3>Settings</h3>
<form method=post class='card p-4' style='max-width:420px'>
  <label>Cancellation cutoff (minutes)</label>
  <input class='form-control mb-3' type=number name=cutoff value='{{ cutoff }}' min=0>
  <button class='btn btn-primary'>Save</button>
</form>
{% endblock %}""",

"profile.html": """{% extends 'base.html' %}{% block title %}Profile{% endblock %}{% block content %}
<h3>My Profile</h3>
<p>Name: {{ current_user.name }}<br>Email: {{ current_user.email }}<br>Role: {{ current_user.role }}</p>
{% endblock %}""",

"errors/403.html": """{% extends 'base.html' %}{% block title %}Forbidden{% endblock %}{% block content %}<h3>403 — Forbidden</h3><p>You do not have permission to access this page.</p>{% endblock %}""",
"errors/404.html": """{% extends 'base.html' %}{% block title %}Not Found{% endblock %}{% block content %}<h3>404 — Not Found</h3><p>The page you requested does not exist.</p>{% endblock %}""",
}

# On first run, ensure templates exist
if __name__ == "__main__":
    os.makedirs("templates/admin", exist_ok=True)
    os.makedirs("templates/errors", exist_ok=True)
    if not os.path.exists("templates/base.html"):
        with open("templates/base.html", "w", encoding="utf-8") as f: f.write(BASE)
    for name, src in TPLS.items():
        path = os.path.join("templates", name)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f: f.write(src)

# -------------------- DB INIT & SEED --------------------
with app.app_context():
    db.create_all()
    # Seed a default admin & verifier if not present
    if not User.query.filter_by(email="admin@example.com").first():
        admin = User(name="Admin", email="admin@example.com", role="admin")
        admin.set_password("Admin123!")
        db.session.add(admin)
    if not User.query.filter_by(email="verifier@example.com").first():
        vr = User(name="Verifier", email="verifier@example.com", role="verifier")
        vr.set_password("Verify123!")
        db.session.add(vr)
    db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)
