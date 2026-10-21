import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.auth.security import decode_access_token
from app.config import settings
from app.db import get_db
from app.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_current_user(token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_error = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials")
    if not token:
        raise credentials_error
    try:
        payload = decode_access_token(token)
    except jwt.PyJWTError:
        raise credentials_error
    username = payload.get("sub")
    if not username:
        raise credentials_error
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise credentials_error
    return user


def require_role(*roles: str):
    def checker(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized")
        return user

    return checker


def require_collector_key(x_collector_key: str | None = Header(default=None)) -> None:
    if not x_collector_key or x_collector_key != settings.collector_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid collector key")
