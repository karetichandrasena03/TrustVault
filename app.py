import os
import uuid
from dotenv import load_dotenv

load_dotenv()
from werkzeug.utils import secure_filename

from flask import Flask, send_from_directory, send_file
from io import BytesIO
from flask import render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import db, User, Document, AuditLog, DocumentPermission
from supabase import create_client
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = None

if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 11 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(app.instance_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
database_url = os.getenv("DATABASE_URL")

if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

if database_url and database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://",
        "postgresql+psycopg2://",
        1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url or "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def record_audit(event_type, document_id=None, details=None):
    log = AuditLog(
        actor_id=current_user.id if current_user.is_authenticated else None,
        document_id=document_id,
        event_type=event_type,
        details=details
    )

    db.session.add(log)
    db.session.commit()

with app.app_context():
    db.create_all()


    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if admin_username and admin_password:
        existing_admin = User.query.filter_by(
            username=admin_username
        ).first()

        if not existing_admin:
            new_admin = User(
                username=admin_username,
                password_hash=generate_password_hash(admin_password),
                role="admin"
            )

            db.session.add(new_admin)
            db.session.commit()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter username and password.")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists.")
            return redirect(url_for("register"))

        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            role="viewer"
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!")
            return redirect(url_for("home"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/")
@login_required
def home():
    admin_links = ""

    if current_user.role == "admin":
        admin_links = """
        <a href="/audit">Audit Trail</a><br><br>
        <a href="/admin-dashboard">Admin Dashboard</a><br><br>
        """

    return f"""
    <h1>Welcome to TrustVault</h1>
    <h2>Secure Document Sharing Platform</h2>
    <p>Database is connected!</p>
    <p>Logged in as: {current_user.username}</p>

    <a href="/upload">Upload Document</a><br><br>
    <a href="/documents">My Documents</a><br><br>
    <a href="/shared-documents">Shared With Me</a><br><br>
    <a href="/permissions">Document Permissions</a><br><br>

    {admin_links}

    <a href="/logout">Logout</a>
    """


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_page():

    if current_user.role != "admin":
        flash("Access denied. Admin only.")
        return redirect(url_for("home"))

    if request.method == "POST":

        uploaded_file = request.files.get("document")
        category = request.form.get("category", "").strip()

        if not uploaded_file or uploaded_file.filename == "":
            flash("Please select a document.")
            return redirect(url_for("upload_page"))

        filename = secure_filename(uploaded_file.filename)

        if not filename:
            flash("Invalid filename.")
            return redirect(url_for("upload_page"))

        allowed_extensions = {
            "pdf", "doc", "docx", "txt",
            "jpg", "jpeg", "png"
        }

        if "." not in filename:
            flash("File must have a valid extension.")
            return redirect(url_for("upload_page"))

        extension = filename.rsplit(".", 1)[1].lower()

        if extension not in allowed_extensions:
            flash("File type not allowed.")
            return redirect(url_for("upload_page"))

        file_data = uploaded_file.read()

        max_file_size = 10 * 1024 * 1024

        if len(file_data) > max_file_size:
            flash("File size must not exceed 10 MB.")
            return redirect(url_for("upload_page"))

        if len(file_data) == 0:
            flash("Empty files are not allowed.")
            return redirect(url_for("upload_page"))

        if supabase is None:
            flash("Document storage is not configured.")
            return redirect(url_for("upload_page"))

        storage_path = f"{current_user.id}/{uuid.uuid4().hex}_{filename}"

        try:
            supabase.storage.from_("trustvault-documents").upload(
                storage_path,
                file_data,
                file_options={
                    "content-type": uploaded_file.mimetype or "application/octet-stream",
                    "upsert": "false"
                }
            )

            document = Document(
                filename=filename,
                file_path=storage_path,
                category=category,
                owner_id=current_user.id
            )

            db.session.add(document)
            db.session.commit()

            record_audit(
                "DOCUMENT_UPLOADED",
                document.id,
                f"User {current_user.username} uploaded {filename}"
            )

            flash("Document uploaded successfully!")

        except Exception as e:
            db.session.rollback()
            print("Supabase upload error:", e)
            flash("Document upload failed. Please try again.")

        return redirect(url_for("upload_page"))

    return render_template("upload.html")


@app.route("/documents")
@login_required
def documents_page():

    search = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()

    documents_query = Document.query.filter_by(
        owner_id=current_user.id
    )

    if search:
        documents_query = documents_query.filter(
            Document.filename.ilike(f"%{search}%")
        )

    if category:
        documents_query = documents_query.filter_by(
            category=category
        )

    documents = documents_query.order_by(
        Document.uploaded_at.desc()
    ).all()

    categories = db.session.query(
        Document.category
    ).filter(
        Document.owner_id == current_user.id,
        Document.category.isnot(None),
        Document.category != ""
    ).distinct().all()

    categories = [item[0] for item in categories]

    return render_template(
        "documents.html",
        documents=documents,
        search=search,
        category=category,
        categories=categories
    )

@app.route("/shared-documents")
@login_required
def shared_documents():

    permissions = DocumentPermission.query.filter_by(
        user_id=current_user.id,
        can_read=True
    ).all()

    documents = []

    for permission in permissions:
        document = db.session.get(Document, permission.document_id)

        if document:
            documents.append(document)

    return render_template(
        "shared_documents.html",
        documents=documents
    )

@app.route("/permissions", methods=["GET", "POST"])
@login_required
def permissions_page():
    if request.method == "POST":

        document_id = request.form.get("document_id", type=int)
        username = request.form.get("username", "").strip()

        can_read = "can_read" in request.form
        can_edit = "can_edit" in request.form

        if can_edit:
            can_read = True

        document = db.session.get(Document, document_id)

        if not document:
            flash("Document not found.")
            return redirect(url_for("permissions_page"))

        if document.owner_id != current_user.id:
            flash("Only the document owner can grant permission.")
            return redirect(url_for("permissions_page"))

        user = User.query.filter_by(username=username).first()

        if not user:
            flash("User not found.")
            return redirect(url_for("permissions_page"))

        if user.id == current_user.id:
            flash("You already own this document.")
            return redirect(url_for("permissions_page"))

        permission = DocumentPermission.query.filter_by(
            document_id=document.id,
            user_id=user.id
        ).first()

        if permission:
            permission.can_read = can_read
            permission.can_edit = can_edit
        else:
            permission = DocumentPermission(
                document_id=document.id,
                user_id=user.id,
                can_read=can_read,
                can_edit=can_edit
            )
            db.session.add(permission)

        db.session.commit()

        record_audit(
            "PERMISSION_GRANTED",
            document.id,
            f"Access granted to {user.username}"
        )

        flash("Permission granted successfully!")
        return redirect(url_for("permissions_page"))

    return render_template("permissions.html")

@app.route("/revoke-permission", methods=["POST"])
@login_required
def revoke_permission():

    document_id = request.form.get("document_id", type=int)
    username = request.form.get("username", "").strip()

    document = db.session.get(Document, document_id)

    if not document:
        flash("Document not found.")
        return redirect(url_for("permissions_page"))

    if document.owner_id != current_user.id:
        flash("Only the document owner can revoke permission.")
        return redirect(url_for("permissions_page"))

    user = User.query.filter_by(username=username).first()

    if not user:
        flash("User not found.")
        return redirect(url_for("permissions_page"))

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=user.id
    ).first()

    if not permission:
        flash("No permission found for this user.")
        return redirect(url_for("permissions_page"))

    db.session.delete(permission)
    db.session.commit()

    record_audit(
        "PERMISSION_REVOKED",
        document.id,
        f"Access revoked from {user.username}"
    )

    flash("Permission revoked successfully!")
    return redirect(url_for("permissions_page"))

@app.route("/edit-document/<int:document_id>", methods=["GET", "POST"])
@login_required
def edit_document(document_id):

    document = Document.query.get_or_404(document_id)

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id,
        can_edit=True
    ).first()

    if document.owner_id != current_user.id and not permission:
        flash("You are not allowed to edit this document.")
        return redirect(url_for("documents_page"))

    if request.method == "POST":
        filename = request.form.get("filename", "").strip()
        category = request.form.get("category", "").strip()

        if not filename:
            flash("Filename cannot be empty.")
            return redirect(url_for("edit_document", document_id=document.id))

        document.filename = secure_filename(filename)
        document.category = category

        db.session.commit()

        record_audit(
            "DOCUMENT_EDITED",
            document.id,
            f"User {current_user.username} edited document details."
        )

        flash("Document updated successfully!")
        return redirect(url_for("documents_page"))

    return render_template("edit_document.html", document=document)

@app.route("/download/<int:document_id>")
@login_required
def download_document(document_id):

    document = Document.query.get_or_404(document_id)

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id,
        can_read=True
    ).first()

    if document.owner_id != current_user.id and not permission:

        record_audit(
            "DOWNLOAD_DENIED",
            document.id,
            f"User {current_user.username} tried to download {document.filename}"
        )

        flash("You are not allowed to download this document.")
        return redirect(url_for("documents_page"))

    if supabase is None:
        flash("Document storage is not configured.")
        return redirect(url_for("documents_page"))

    try:
        file_data = supabase.storage.from_("trustvault-documents").download(
            document.file_path
        )

        record_audit(
            "DOCUMENT_DOWNLOADED",
            document.id,
            f"User {current_user.username} downloaded {document.filename}"
        )

        return send_file(
            BytesIO(file_data),
            as_attachment=True,
            download_name=document.filename
        )

    except Exception as e:
        print("Supabase download error:", e)
        flash("Unable to download this document.")
        return redirect(url_for("documents_page"))

@app.route("/admin-dashboard")
@login_required
def admin_dashboard():

    if current_user.role != "admin":
        flash("Access denied. Admin only.")
        return redirect(url_for("home"))

    total_users = User.query.count()
    total_documents = Document.query.count()
    total_audit_logs = AuditLog.query.count()

    users = User.query.all()
    documents = Document.query.order_by(
        Document.uploaded_at.desc()
    ).all()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_documents=total_documents,
        total_audit_logs=total_audit_logs,
        users=users,
        documents=documents
    )

@app.route("/audit")
@login_required
def audit_page():
    print("AUDIT CHECK:", current_user.username, current_user.role)

    if current_user.role != "admin":
        flash("Access denied. Admin only.")
        return redirect(url_for("home"))

    logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).all()

    return render_template("audit.html", logs=logs)  

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=False)