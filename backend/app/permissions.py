from fastapi import HTTPException
from sqlalchemy.orm import Session
from .models import Collection, CollectionPermission, Secret, SecretShare, User


def collection_access(db: Session, user: User, collection: Collection) -> tuple[bool, bool, bool]:
    if user.role == 'admin' or collection.owner_id == user.id:
        return True, user.role != 'viewer', True
    grant = db.get(CollectionPermission, (collection.id, user.id))
    return (bool(grant and grant.access in ('read', 'write')),
            bool(grant and grant.access == 'write' and user.role != 'viewer'),
            bool(grant and grant.access in ('read', 'write') and grant.can_copy))


def secret_access(db: Session, user: User, secret: Secret) -> tuple[bool, bool, bool]:
    if user.role == 'admin' or secret.owner_id == user.id:
        return True, user.role != 'viewer', True
    grants: list[tuple[bool, bool, bool]] = []
    if secret.collection_id:
        collection = db.get(Collection, secret.collection_id)
        if collection:
            grants.append(collection_access(db, user, collection))
    share = db.get(SecretShare, (secret.id, user.id))
    if share:
        grants.append((share.access in ('read', 'write'), share.access == 'write' and user.role != 'viewer', share.can_copy))
    return tuple(any(grant[index] for grant in grants) for index in range(3))


def access_secret(db: Session, user: User, secret: Secret | None, write: bool = False, copy: bool = False) -> Secret:
    if secret is None:
        raise HTTPException(404, 'Secret not found')
    read, edit, can_copy = secret_access(db, user, secret)
    if not read:
        raise HTTPException(404, 'Secret not found')
    if write and not edit or copy and not can_copy:
        raise HTTPException(403, 'Permission denied')
    return secret


def access_collection(db: Session, user: User, collection_id: str, write: bool = False) -> Collection:
    collection = db.get(Collection, collection_id)
    if collection is None:
        raise HTTPException(404, 'Collection not found')
    read, edit, _ = collection_access(db, user, collection)
    if not read:
        raise HTTPException(404, 'Collection not found')
    if write and not edit:
        raise HTTPException(403, 'Permission denied')
    return collection


def require_collection_owner(user: User, collection: Collection) -> None:
    if user.role != 'admin' and user.id != collection.owner_id:
        raise HTTPException(403, 'Only the owner or administrator can manage permissions')


def require_secret_owner(user: User, secret: Secret) -> None:
    if user.role != 'admin' and user.id != secret.owner_id:
        raise HTTPException(403, 'Only the owner or administrator can share this secret')
