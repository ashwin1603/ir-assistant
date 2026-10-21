from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.config import settings
from app.models import User


def seed_admin_user(db: Session) -> None:
    if not settings.admin_username or not settings.admin_password:
        return
    existing = db.query(User).filter(User.username == settings.admin_username).first()
    if existing:
        return
    db.add(User(username=settings.admin_username, password_hash=hash_password(settings.admin_password), role="admin"))
    db.commit()
