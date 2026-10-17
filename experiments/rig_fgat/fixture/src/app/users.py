from dataclasses import dataclass, field

@dataclass
class Profile:
    user_id: int
    tags: list[str] = field(default_factory=list)
