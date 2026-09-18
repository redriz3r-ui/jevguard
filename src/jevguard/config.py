from dataclasses import dataclass, field
import os


@dataclass(frozen=True)
class Settings:
    typesafe_api_key: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(typesafe_api_key=os.environ.get("TYPESAFE_API_KEY") or None)
