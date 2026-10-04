import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    database_url: str = os.getenv('DATABASE_URL', '')
    data_dir: Path = Path(os.getenv('DATA_DIR', '/data'))
    secure_cookies: bool = os.getenv('SECURE_COOKIES', 'false').lower() == 'true'
    public_url: str = os.getenv('APP_URL', '').rstrip('/')
    max_file_bytes: int = 2 * 1024 * 1024
    max_request_bytes: int = 12 * 1024 * 1024
    cookie_name: str = 'secrets_hub_session'

    def __post_init__(self) -> None:
        if not self.database_url.strip():
            raise ValueError('DATABASE_URL must be configured')


config = Config()
