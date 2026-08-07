from __future__ import annotations

from pathlib import Path

from .config import Settings


class Workspace:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = settings.workspace_root.resolve()
        self._blocked = {name.casefold() for name in settings.blocked_file_names}
        self._excluded = {name.casefold() for name in settings.excluded_directories}

    def _is_inside(self, candidate: Path) -> bool:
        try:
            candidate.relative_to(self.root)
            return True
        except ValueError:
            return candidate == self.root

    def _check_inside(self, candidate: Path) -> None:
        if not self._is_inside(candidate):
            raise PermissionError(f"作業フォルダ外へのアクセスを拒否しました: {candidate}")

    def _check_sensitive(self, candidate: Path) -> None:
        relative_parts = candidate.relative_to(self.root).parts if candidate != self.root else ()
        folded_parts = [part.casefold() for part in relative_parts]

        if any(part == ".git" for part in folded_parts):
            raise PermissionError(".gitディレクトリへの直接アクセスを拒否しました")

        base = candidate.name.casefold()
        if base in self._blocked or (base.startswith(".env.") and base != ".env.example"):
            raise PermissionError(f"秘密情報の可能性があるファイルを拒否しました: {candidate}")

    def resolve_existing(self, user_path: str, *, allow_directory: bool = True) -> Path:
        lexical = (self.root / user_path).resolve(strict=True)
        self._check_inside(lexical)
        self._check_sensitive(lexical)
        if not allow_directory and not lexical.is_file():
            raise IsADirectoryError(f"ファイルではありません: {lexical}")
        return lexical

    def resolve_directory(self, user_path: str) -> Path:
        path = self.resolve_existing(user_path, allow_directory=True)
        if not path.is_dir():
            raise NotADirectoryError(f"ディレクトリではありません: {path}")
        return path

    def resolve_for_write(self, user_path: str) -> Path:
        lexical = self.root / user_path
        parent = lexical.parent.resolve(strict=True)
        self._check_inside(parent)
        target = (parent / lexical.name).resolve(strict=False)
        self._check_inside(target)
        self._check_sensitive(target)
        return target

    def relative(self, path: Path) -> str:
        return str(path.resolve(strict=False).relative_to(self.root))

    def is_excluded(self, path: Path) -> bool:
        try:
            parts = path.relative_to(self.root).parts
        except ValueError:
            return True
        return any(part.casefold() in self._excluded for part in parts)
