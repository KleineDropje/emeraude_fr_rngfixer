#!/usr/bin/env python3
"""Construit une copie corrigée de Pokémon Version Émeraude française.

Le programme accepte uniquement la ROM propre française, contrôle ses
empreintes et ses zones critiques, applique trois modifications binaires à
une copie, puis vérifie intégralement le résultat. La source est ouverte en
lecture et n'est pas utilisée comme destination d'écriture.

Correctif original : MWisBest
https://www.pokecommunity.com/attachments/emerald-32-bit-rtc-timer-rng-fix-ips.81587/

Portage français : KleineDropje

Prérequis : Python 3.9 ou version ultérieure, sans dépendance externe ; une
version de Python encore maintenue est recommandée.
Systèmes pris en charge : Windows 10/11, macOS 10.15 ou ultérieur et Linux.
Pour isoler également l'interpréteur d'un environnement Python non fiable,
le script doit être lancé avec l'option standard « -I » de Python.
"""

from __future__ import annotations

import sys

# Le programme n'importe aucun module local. En exécution directe, retirer
# l'emplacement ajouté par Python empêche un fichier voisin d'usurper le nom
# d'un module de la bibliothèque standard.
if __name__ == "__main__" and not sys.flags.isolated and sys.path:
    del sys.path[0]

import argparse
import hashlib
import os
import shlex
import stat
import unicodedata
from contextlib import ExitStack
from pathlib import Path, PureWindowsPath
from typing import BinaryIO


ROM_SIZE = 16 * 1024 * 1024
EXPECTED_SOURCE_MD5 = "2c00e335288a96650e34785b5e2a7588"
EXPECTED_SOURCE_SHA1 = "ca666651374d89ca439007bed54d839eb7bd14d0"
EXPECTED_SOURCE_SHA256 = (
    "e79b40e6189550b4870b06918a5c59e04d3a2e1d7c92718aeda92181201f51e4"
)
EXPECTED_PATCHED_MD5 = "db02a1ba1e3787114dea02547f8515b2"
EXPECTED_PATCHED_SHA1 = "a6bfff331ae78f7c284104074404c7d4f1593cd1"
OUTPUT_SUFFIX = " - RTC+TIMER RNG Fix FR.gba"
MAX_OUTPUT_ATTEMPTS = 1_000
MAX_RECOVERY_ENTRIES = 10_000
MAX_INPUT_CHARACTERS = 65_536

# Le programme est mono-processus. Cette référence sert uniquement à signaler
# une sortie potentiellement incomplète si une erreur survient après sa création.
_active_output_path: Path | None = None

HOOK_OFFSET = 0x000400
HOOK_ORIGINAL = bytes.fromhex("1d 48 00 24 04 70")
HOOK_PATCHED = bytes.fromhex("00 f0 a8 f8 c0 46")

POINTER_OFFSET = 0x0AAEE4
POINTER_ORIGINAL = bytes.fromhex("dd f6 02 08")
POINTER_PATCHED_FIRST_THREE = bytes.fromhex("71 4f 9c")

INJECTION_BASE = 0x9C4F70
INJECTION_OFFSET = 0x9C4F71
INJECTION_SIZE = 68
# Le pointeur Thumb est impair (0x089C4F71), mais l'exécution commence à
# 0x089C4F70 après retrait du bit d'état. L'octet nul déjà présent à la base
# forme donc, avec le premier octet injecté, l'instruction initiale 00 b5.
ROUTINE_TAIL = bytes.fromhex(
    "b5 00 20 0a 49 c8 80 0c 49 00 f0 10 f8 01 0c 41 40 "
    "07 48 80 88 09 04 08 43 06 49 08 60 06 49 08 60 "
    "00 20 06 49 00 f0 02 f8 01 bc 00 47 08 47 00 01 00 "
    "04 80 5d 00 03 00 00 02 02 65 f6 02 08 f5 f6 02 08"
)
PATCH_WRITES = (
    (HOOK_OFFSET, HOOK_PATCHED),
    (POINTER_OFFSET, POINTER_PATCHED_FIRST_THREE),
    (INJECTION_OFFSET, ROUTINE_TAIL),
)

# Signatures relevées dans la ROM française propre.
CRITICAL_CHECKS = (
    (HOOK_OFFSET, HOOK_ORIGINAL, "zone du hook dans AgbMain"),
    (0x000554, bytes.fromhex("01 49 80 20 08 80 70 47"), "StartTimer1"),
    (0x02F664, bytes.fromhex("10 b5 0c 4c"), "RtcGetMinuteCount"),
    (0x02F6F4, bytes.fromhex("30 b5 83 b0"), "InitMainMenu"),
    (POINTER_OFFSET, POINTER_ORIGINAL, "pointeur CB2_InitMainMenu"),
)


class PatcherError(Exception):
    pass


class OutputExistsError(PatcherError):
    pass


class InputClosedError(PatcherError):
    pass


def validate_patch_definition() -> None:
    """Vérifie les invariants internes du portage avant toute écriture."""
    hash_constants = (
        (EXPECTED_SOURCE_MD5, 32),
        (EXPECTED_SOURCE_SHA1, 40),
        (EXPECTED_SOURCE_SHA256, 64),
        (EXPECTED_PATCHED_MD5, 32),
        (EXPECTED_PATCHED_SHA1, 40),
    )
    if any(
        len(value) != expected_length
        or any(character not in "0123456789abcdef" for character in value)
        for value, expected_length in hash_constants
    ):
        raise PatcherError("erreur interne : empreinte de référence invalide.")

    if len(ROUTINE_TAIL) != 67:
        raise PatcherError("erreur interne : la routine doit contenir 67 octets.")
    if len(PATCH_WRITES) != 3:
        raise PatcherError("erreur interne : trois écritures sont requises.")
    if len(HOOK_ORIGINAL) != 6 or len(HOOK_PATCHED) != 6:
        raise PatcherError("erreur interne : définition du hook incohérente.")
    if INJECTION_OFFSET != INJECTION_BASE + 1:
        raise PatcherError("erreur interne : offset d'injection incohérent.")
    if INJECTION_SIZE != len(ROUTINE_TAIL) + 1:
        raise PatcherError(
            "erreur interne : taille de la zone d'injection incohérente."
        )
    if len(POINTER_ORIGINAL) != 4 or len(POINTER_PATCHED_FIRST_THREE) != 3:
        raise PatcherError("erreur interne : définition du pointeur incohérente.")
    patched_pointer = POINTER_PATCHED_FIRST_THREE + POINTER_ORIGINAL[3:]
    if int.from_bytes(patched_pointer, "little") != 0x089C4F71:
        raise PatcherError("erreur interne : adresse Thumb incohérente.")
    if b"\x00" + ROUTINE_TAIL[:1] != b"\x00\xb5":
        raise PatcherError("erreur interne : première instruction Thumb incohérente.")
    if sum(len(replacement) for _, replacement in PATCH_WRITES) != 76:
        raise PatcherError("erreur interne : volume des modifications incohérent.")

    occupied = set()
    for offset, replacement in PATCH_WRITES:
        positions = set(range(offset, offset + len(replacement)))
        if offset < 0 or offset + len(replacement) > ROM_SIZE:
            raise PatcherError("erreur interne : écriture hors des limites de la ROM.")
        if occupied.intersection(positions):
            raise PatcherError("erreur interne : zones de modification superposées.")
        occupied.update(positions)

    for offset, expected, _label in CRITICAL_CHECKS:
        if offset < 0 or offset + len(expected) > ROM_SIZE:
            raise PatcherError("erreur interne : contrôle critique hors limites.")


def is_invisible_unicode(character: str) -> bool:
    codepoint = ord(character)
    return (
        unicodedata.category(character) == "Cf"
        or codepoint == 0x034F
        or 0x17B4 <= codepoint <= 0x17B5
        or 0x180B <= codepoint <= 0x180D
        or 0xFE00 <= codepoint <= 0xFE0F
        or 0xE0100 <= codepoint <= 0xE01EF
    )


def terminal_safe_text(value: object, preserve_newlines: bool = False) -> str:
    """Rend le texte visible sans laisser de séquence de contrôle active."""
    escaped = []
    for character in str(value):
        if preserve_newlines and character == "\n":
            escaped.append(character)
        elif unicodedata.category(character).startswith("C"):
            escaped.append(ascii(character)[1:-1])
        else:
            escaped.append(character)
    return "".join(escaped)


def new_identifier_hash(algorithm: str):
    # Ces empreintes identifient une ROM connue mais elles n'en authentifient pas la
    # provenance. L'indication explicite maintient leur disponibilité en mode FIPS.
    try:
        return hashlib.new(algorithm, usedforsecurity=False)
    except (TypeError, ValueError) as exc:
        raise PatcherError(
            f"l'algorithme d'empreinte {algorithm} n'est pas disponible."
        ) from exc


class PatcherArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise PatcherError(
            f"arguments de commande invalides : {terminal_safe_text(message)}"
        )


def hashes_from_data(data: bytes | bytearray) -> tuple[str, str, str]:
    md5_hasher = new_identifier_hash("md5")
    sha1_hasher = new_identifier_hash("sha1")
    sha256_hasher = new_identifier_hash("sha256")
    md5_hasher.update(data)
    sha1_hasher.update(data)
    sha256_hasher.update(data)
    return (
        md5_hasher.hexdigest(),
        sha1_hasher.hexdigest(),
        sha256_hasher.hexdigest(),
    )


def file_state(file_info: os.stat_result) -> tuple[int, int, int, int]:
    return (
        file_info.st_dev,
        file_info.st_ino,
        file_info.st_size,
        file_info.st_mtime_ns,
    )


def require_open_file_state(
    stream: BinaryIO,
    expected_state: tuple[int, int, int, int],
) -> None:
    try:
        current_state = file_state(os.fstat(stream.fileno()))
    except OSError as exc:
        raise PatcherError(
            "impossible de contrôler l'état du fichier ouvert."
        ) from exc
    if current_state != expected_state:
        raise PatcherError("le fichier ouvert a changé après sa vérification.")


def require_distinct_open_files(first: BinaryIO, second: BinaryIO) -> None:
    try:
        first_info = os.fstat(first.fileno())
        second_info = os.fstat(second.fileno())
    except OSError as exc:
        raise PatcherError("impossible de comparer les fichiers ouverts.") from exc
    if os.path.samestat(first_info, second_info):
        raise PatcherError(
            "la source et la sortie désignent le même fichier ; écriture refusée."
        )


def hashes_from_open_file(
    stream: BinaryIO,
    expected_size: int,
) -> tuple[str, str, str, tuple[int, int, int, int]]:
    md5_hasher = new_identifier_hash("md5")
    sha1_hasher = new_identifier_hash("sha1")
    sha256_hasher = new_identifier_hash("sha256")
    remaining = expected_size
    try:
        before_state = file_state(os.fstat(stream.fileno()))
        stream.seek(0)

        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                raise PatcherError("la taille du fichier a changé pendant sa lecture.")
            md5_hasher.update(chunk)
            sha1_hasher.update(chunk)
            sha256_hasher.update(chunk)
            remaining -= len(chunk)

        if stream.read(1):
            raise PatcherError("la taille du fichier a changé pendant sa lecture.")

        file_info = os.fstat(stream.fileno())
    except OSError as exc:
        raise PatcherError(
            "impossible de vérifier le fichier ouvert : "
            f"{terminal_safe_text(exc)}"
        ) from exc

    after_state = file_state(file_info)
    if (
        not stat.S_ISREG(file_info.st_mode)
        or file_info.st_size != expected_size
        or after_state != before_state
    ):
        raise PatcherError("le fichier ouvert a changé pendant sa vérification.")

    return (
        md5_hasher.hexdigest(),
        sha1_hasher.hexdigest(),
        sha256_hasher.hexdigest(),
        after_state,
    )


def stat_without_following_symlinks(path: Path) -> os.stat_result:
    return os.stat(path, follow_symlinks=False)


def close_fd_safely(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def require_path_matches_open_file(
    path: Path,
    stream: BinaryIO,
    directory_fd: int | None = None,
) -> None:
    try:
        if directory_fd is None:
            path_info = stat_without_following_symlinks(path)
        else:
            path_info = os.stat(
                path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
    except OSError as exc:
        raise PatcherError(
            "le chemin du fichier ouvert a disparu ou est inaccessible : "
            f"{terminal_safe_text(path)}"
        ) from exc

    try:
        opened_info = os.fstat(stream.fileno())
    except OSError as exc:
        raise PatcherError("impossible de contrôler le fichier ouvert.") from exc
    if not stat.S_ISREG(path_info.st_mode) or not os.path.samestat(
        path_info, opened_info
    ):
        raise PatcherError(
            "le chemin a été remplacé pendant l'exécution : "
            f"{terminal_safe_text(path)}"
        )


def open_source_file(path: Path) -> BinaryIO:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)

    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PatcherError(
            f"impossible d'ouvrir la ROM en lecture : {terminal_safe_text(exc)}"
        ) from exc

    try:
        file_info = os.fstat(fd)
        if not stat.S_ISREG(file_info.st_mode):
            raise PatcherError("le chemin ne désigne pas un fichier ordinaire.")
        return os.fdopen(fd, "rb")
    except BaseException:
        close_fd_safely(fd)
        raise


def open_output_directory(path: Path) -> tuple[int | None, os.stat_result]:
    try:
        path_info = stat_without_following_symlinks(path)
    except OSError as exc:
        raise PatcherError(
            "impossible de contrôler le dossier de sortie : "
            f"{terminal_safe_text(exc)}"
        ) from exc

    if not stat.S_ISDIR(path_info.st_mode):
        raise PatcherError("le dossier de sortie n'est plus un répertoire ordinaire.")

    if os.name == "nt" or not hasattr(os, "O_DIRECTORY"):
        return None, path_info

    flags = os.O_RDONLY | os.O_DIRECTORY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        directory_fd = os.open(path, flags)
        opened_info = os.fstat(directory_fd)
        if not os.path.samestat(path_info, opened_info):
            raise PatcherError("le dossier de sortie a été remplacé.")
        return directory_fd, opened_info
    except BaseException:
        if "directory_fd" in locals():
            close_fd_safely(directory_fd)
        raise


def require_output_directory_unchanged(
    path: Path,
    expected_info: os.stat_result,
    directory_fd: int | None,
) -> None:
    try:
        current_info = stat_without_following_symlinks(path)
    except OSError as exc:
        raise PatcherError(
            "le dossier de sortie a disparu ou est inaccessible."
        ) from exc

    if not stat.S_ISDIR(current_info.st_mode) or not os.path.samestat(
        current_info, expected_info
    ):
        raise PatcherError(
            "le dossier de sortie a été remplacé pendant l'exécution."
        )

    if directory_fd is not None:
        try:
            opened_info = os.fstat(directory_fd)
        except OSError as exc:
            raise PatcherError("impossible de contrôler le dossier ouvert.") from exc
        if not os.path.samestat(opened_info, expected_info):
            raise PatcherError("l'identité du dossier de sortie a changé.")


def clean_path_text(
    raw: str,
    platform_name: str,
    interpret_shell_escapes: bool = True,
) -> str:
    if "\x00" in raw:
        raise PatcherError("le chemin contient un octet nul interdit.")

    # Certains glisser-déposer ajoutent des caractères Unicode invisibles.
    value = "".join(
        character
        for character in raw
        if not is_invisible_unicode(character)
    ).strip()
    if not value:
        raise PatcherError("aucun chemin de ROM n'a été fourni.")

    if interpret_shell_escapes and platform_name != "nt":
        # Un glisser-déposer peut produire une représentation échappée du chemin.
        try:
            shell_parts = shlex.split(value, posix=True)
        except ValueError:
            shell_parts = []
        if len(shell_parts) == 1:
            value = shell_parts[0]
    elif (
        interpret_shell_escapes
        and len(value) >= 2
        and value[0] == value[-1]
        and value[0] in {'"', "'"}
    ):
        # Certaines invites entourent les chemins contenant des espaces.
        value = value[1:-1]

    validate_local_path_syntax(value, platform_name)
    return value


def validate_local_path_syntax(value: str, platform_name: str) -> None:
    """Écarte les espaces de noms qui ne désignent pas un fichier local normal."""
    if platform_name != "nt":
        return

    normalized = value.replace("/", "\\")
    windows_path = PureWindowsPath(value)
    if normalized.startswith("\\\\"):
        raise PatcherError(
            "les chemins réseau UNC et les espaces de noms de périphériques "
            "Windows ne sont pas acceptés. Utilisez une ROM stockée localement."
        )
    components = tuple(
        component
        for component in windows_path.parts
        if component not in {windows_path.anchor, ".", ".."}
    )
    if windows_path.is_reserved() or any(
        is_reserved_windows_component(component) for component in components
    ):
        raise PatcherError(
            "ce nom est réservé par Windows et ne désigne pas une ROM."
        )

    remainder = value[len(windows_path.drive) :]
    if ":" in remainder:
        raise PatcherError(
            "les flux de données alternatifs Windows ne sont pas acceptés."
        )

    if any(component.endswith((" ", ".")) for component in components):
        raise PatcherError(
            "un composant du chemin se termine par un espace ou un point, "
            "syntaxe ambiguë sous Windows."
        )


def is_reserved_windows_component(component: str) -> bool:
    """Reconnaît les noms de périphériques Windows, variantes Unicode incluses."""
    normalized = unicodedata.normalize("NFKC", component.rstrip(" ."))
    stem = normalized.split(".", 1)[0].casefold()
    if stem in {"con", "prn", "aux", "nul", "conin$", "conout$"}:
        return True
    return (
        len(stem) == 4
        and stem[:3] in {"com", "lpt"}
        and stem[3] in "123456789"
    )


def clean_interactive_path(raw: str) -> Path:
    return expand_user_path(clean_path_text(raw, os.name))


def clean_argument_path(raw: str) -> Path:
    # Le shell a déjà interprété les échappements d'un argument de commande.
    return expand_user_path(
        clean_path_text(raw, os.name, interpret_shell_escapes=False)
    )


def expand_user_path(value: str) -> Path:
    try:
        return Path(value).expanduser()
    except (OSError, RuntimeError) as exc:
        raise PatcherError(
            "impossible de résoudre le dossier personnel dans ce chemin."
        ) from exc


def path_lookup_key(name: str) -> str:
    normalized = unicodedata.normalize("NFKC", name)
    visible = "".join(
        character
        for character in normalized
        if not is_invisible_unicode(character)
    )
    # Recherche de secours tolérante aux espaces Unicode et à la casse.
    return " ".join(visible.split()).casefold()


def resolve_existing_path(supplied_path: Path) -> tuple[Path, bool]:
    """Résout exactement le chemin, puis tente un rapprochement non ambigu."""
    try:
        return supplied_path.resolve(strict=True), False
    except (OSError, RuntimeError, ValueError) as original_error:
        try:
            parent = supplied_path.parent.resolve(strict=True)
            if not parent.is_dir():
                raise OSError("le dossier parent n'est pas un répertoire")
            wanted_key = path_lookup_key(supplied_path.name)
            matches = []
            with os.scandir(parent) as entries:
                for entry_number, entry in enumerate(entries, start=1):
                    if entry_number > MAX_RECOVERY_ENTRIES:
                        raise PatcherError(
                            "recherche de secours interrompue : le dossier contient "
                            f"plus de {MAX_RECOVERY_ENTRIES} éléments."
                        )
                    if (
                        entry.is_file(follow_symlinks=True)
                        and path_lookup_key(entry.name) == wanted_key
                    ):
                        matches.append(Path(entry.path))
                        if len(matches) > 1:
                            break
        except PatcherError:
            raise
        except (OSError, RuntimeError, ValueError):
            matches = []

        if len(matches) == 1:
            return matches[0].resolve(strict=True), True

        technical_path = ascii(str(supplied_path))
        ambiguity = (
            f" ({len(matches)} correspondances possibles)" if matches else ""
        )
        raise PatcherError(
            "fichier introuvable ou inaccessible : "
            f"{terminal_safe_text(supplied_path)}\n"
            f"  Représentation technique : {technical_path}{ambiguity}"
        ) from original_error


def show_bytes(data: bytes) -> str:
    return data.hex(" ")


def require_bytes(data: bytes, offset: int, expected: bytes, label: str) -> None:
    actual = data[offset : offset + len(expected)]
    if actual != expected:
        raise PatcherError(
            f"vérification binaire échouée pour {label}.\n"
            f"  Offset  : 0x{offset:06X}\n"
            f"  Attendu : {show_bytes(expected)}\n"
            f"  Trouvé  : {show_bytes(actual)}\n"
            "Aucune donnée n'a été écrite."
        )


def validate_critical_bytes(original: bytes) -> None:
    for offset, expected, label in CRITICAL_CHECKS:
        require_bytes(original, offset, expected, label)
    print(f"  [OK] {len(CRITICAL_CHECKS)} signatures critiques conformes")

    injection_zone = original[INJECTION_BASE : INJECTION_BASE + INJECTION_SIZE]
    if injection_zone != b"\x00" * INJECTION_SIZE:
        first_difference = next(
            index for index, value in enumerate(injection_zone) if value != 0
        )
        bad_offset = INJECTION_BASE + first_difference
        raise PatcherError(
            "la zone réservée à l'injection n'est pas libre.\n"
            f"  Zone contrôlée : 0x{INJECTION_BASE:06X}–"
            f"0x{INJECTION_BASE + INJECTION_SIZE - 1:06X}\n"
            f"  Premier octet non nul : 0x{bad_offset:06X}\n"
            "Aucune donnée n'a été écrite."
        )
    print(
        f"  [OK] zone d'injection libre : 0x{INJECTION_BASE:06X}–"
        f"0x{INJECTION_BASE + INJECTION_SIZE - 1:06X} "
        f"({INJECTION_SIZE} octets nuls)"
    )


def build_patched_rom(original: bytes) -> bytes:
    """Valide les zones critiques puis applique exactement trois écritures."""
    validate_critical_bytes(original)
    return apply_patch_writes(original)


def apply_patch_writes(original: bytes) -> bytes:
    """Construit la copie en mémoire à partir des trois écritures autorisées."""
    validate_patch_definition()

    patched = bytearray(original)
    for offset, replacement in PATCH_WRITES:
        patched[offset : offset + len(replacement)] = replacement

    if len(patched) != len(original):
        raise PatcherError("erreur interne : la taille de la ROM a changé.")

    for offset, replacement in PATCH_WRITES:
        if patched[offset : offset + len(replacement)] != replacement:
            raise PatcherError(
                "erreur interne : une modification n'a pas été appliquée."
            )

    return bytes(patched)


def open_exclusive_output(path: Path, directory_fd: int | None) -> BinaryIO:
    """Crée un nouveau fichier et refuse strictement tout écrasement."""
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)

    try:
        # Demande les droits minimaux de lecture et d'écriture. Sur un système
        # appliquant les modes POSIX, seul le propriétaire reçoit ces droits.
        if directory_fd is None:
            fd = os.open(path, flags, 0o600)
        else:
            fd = os.open(path.name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError as exc:
        raise OutputExistsError(
            f"le fichier de sortie existe déjà : {terminal_safe_text(path)}"
        ) from exc
    except OSError as exc:
        raise PatcherError(
            "impossible de créer la ROM de sortie : "
            f"{terminal_safe_text(exc)}"
        ) from exc

    try:
        file_info = os.fstat(fd)
        if not stat.S_ISREG(file_info.st_mode):
            raise PatcherError("la sortie créée n'est pas un fichier ordinaire.")
        return os.fdopen(fd, "w+b", buffering=0)
    except BaseException:
        close_fd_safely(fd)
        raise


def write_open_file(stream: BinaryIO, data: bytes) -> None:
    stream.seek(0)
    remaining = memoryview(data)
    while remaining:
        written = stream.write(remaining)
        if not written:
            raise PatcherError("l'écriture de la ROM de sortie est incomplète.")
        remaining = remaining[written:]
    stream.flush()
    os.fsync(stream.fileno())


def numbered_output_path(rom_path: Path, number: int) -> Path:
    base_stem = rom_path.stem + OUTPUT_SUFFIX.removesuffix(".gba")
    numbered_suffix = "" if number == 0 else f" ({number})"
    return rom_path.with_name(base_stem + numbered_suffix + ".gba")


def create_numbered_output(
    rom_path: Path,
    directory_fd: int | None,
    directory_info: os.stat_result,
) -> tuple[Path, BinaryIO]:
    for number in range(MAX_OUTPUT_ATTEMPTS):
        require_output_directory_unchanged(
            rom_path.parent,
            directory_info,
            directory_fd,
        )
        candidate = numbered_output_path(rom_path, number)
        try:
            output = open_exclusive_output(candidate, directory_fd)
        except OutputExistsError:
            continue

        try:
            require_path_matches_open_file(candidate, output, directory_fd)
        except BaseException:
            output.close()
            raise
        return candidate, output

    raise PatcherError(
        f"aucun nom de sortie disponible parmi {MAX_OUTPUT_ATTEMPTS} possibilités."
    )


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = PatcherArgumentParser(
        prog=terminal_safe_text(Path(sys.argv[0]).name),
        allow_abbrev=False,
        description=(
            "Crée une copie de Pokémon Version Émeraude FR avec le correctif "
            "RTC+TIMER RNG, sans modifier la ROM originale."
        )
    )
    parser.add_argument(
        "rom",
        nargs="?",
        help="chemin de la ROM française propre au format .gba",
    )
    return parser.parse_args(argv)


def patch_rom(rom_path: Path) -> Path:
    global _active_output_path
    _active_output_path = None

    with ExitStack() as resources:
        source = resources.enter_context(open_source_file(rom_path))
        require_path_matches_open_file(rom_path, source)

        directory_fd, directory_info = open_output_directory(rom_path.parent)
        if directory_fd is not None:
            resources.callback(close_fd_safely, directory_fd)
        require_output_directory_unchanged(
            rom_path.parent,
            directory_info,
            directory_fd,
        )
        require_path_matches_open_file(rom_path, source)

        print("\n[2/5] Identification stricte de la ROM")
        source_info = os.fstat(source.fileno())
        source_size = source_info.st_size
        print(
            f"  Taille obtenue : {source_size} octets "
            f"({source_size / 1048576:.2f} MiB)"
        )
        print(f"  Taille attendue: {ROM_SIZE} octets (16.00 MiB)")
        if source_size != ROM_SIZE:
            raise PatcherError(
                "taille incompatible. La ROM doit faire exactement 16 MiB.\n"
                "Aucune donnée n'a été écrite."
            )
        print("  [OK] taille et fichier OK")

        try:
            source_state_before_read = file_state(os.fstat(source.fileno()))
            source.seek(0)
            original = source.read(ROM_SIZE + 1)
            source_state_after_read = file_state(os.fstat(source.fileno()))
        except OSError as exc:
            raise PatcherError(
                f"impossible de lire la ROM : {terminal_safe_text(exc)}"
            ) from exc
        if (
            len(original) != ROM_SIZE
            or source_state_after_read[2] != ROM_SIZE
            or source_state_after_read != source_state_before_read
        ):
            raise PatcherError(
                "la ROM a changé pendant sa lecture.\n"
                "Aucune donnée n'a été écrite."
            )
        require_path_matches_open_file(rom_path, source)

        source_md5, source_sha1, source_sha256 = hashes_from_data(original)
        print(f"  MD5 obtenu : {source_md5}")
        print(f"  SHA1 obtenu: {source_sha1}")
        print(f"  SHA256 obtenu: {source_sha256}")

        if source_md5 == EXPECTED_PATCHED_MD5 and source_sha1 == EXPECTED_PATCHED_SHA1:
            raise PatcherError("cette ROM est déjà patchée.")
        if (
            source_md5 != EXPECTED_SOURCE_MD5
            or source_sha1 != EXPECTED_SOURCE_SHA1
            or source_sha256 != EXPECTED_SOURCE_SHA256
        ):
            raise PatcherError(
                "ROM refusée : ce n'est pas la ROM française propre attendue.\n"
                f"  MD5 attendu : {EXPECTED_SOURCE_MD5}\n"
                f"  MD5 obtenu  : {source_md5}\n"
                f"  SHA1 attendu: {EXPECTED_SOURCE_SHA1}\n"
                f"  SHA1 obtenu : {source_sha1}\n"
                f"  SHA256 attendu: {EXPECTED_SOURCE_SHA256}\n"
                f"  SHA256 obtenu : {source_sha256}\n"
                "La ROM ne peut appartenir à une autre région, être une autre révision, "
                "être déjà modifiée ou bien être corrompue. "
                "Veuillez insérer une ROM de Pokémon Émeraude Française."
            )
        print("  [OK] empreintes de Pokémon Version Émeraude (France), ROM propre")

        print("\n[3/5] Vérification préalable des octets critiques")
        validate_patch_definition()
        validate_critical_bytes(original)

        print("\n[4/5] Application contrôlée des trois modifications")
        patched = apply_patch_writes(original)
        print(
            f"  [OK] 0x{HOOK_OFFSET:06X} : "
            f"{show_bytes(HOOK_ORIGINAL)} -> {show_bytes(HOOK_PATCHED)}"
        )
        print(
            f"  [OK] 0x{POINTER_OFFSET:06X} : "
            f"{show_bytes(POINTER_ORIGINAL[:3])} -> "
            f"{show_bytes(POINTER_PATCHED_FIRST_THREE)} (octet final 08 conservé)"
        )
        print(
            f"  [OK] 0x{INJECTION_OFFSET:06X} : "
            f"routine de {len(ROUTINE_TAIL)} octets injectée"
        )
        print(
            "  [OK] trois zones seulement, soit 76 octets modifiés "
            "par rapport à la source"
        )

        patched_md5, patched_sha1, patched_sha256 = hashes_from_data(patched)
        print(f"  MD5 calculé : {patched_md5}")
        print(f"  SHA1 calculé: {patched_sha1}")
        print(f"  SHA256 calculé: {patched_sha256}")
        if patched_md5 != EXPECTED_PATCHED_MD5 or patched_sha1 != EXPECTED_PATCHED_SHA1:
            raise PatcherError(
                "la vérification finale en mémoire a échoué.\n"
                f"  MD5 attendu : {EXPECTED_PATCHED_MD5}\n"
                f"  MD5 obtenu  : {patched_md5}\n"
                f"  SHA1 attendu: {EXPECTED_PATCHED_SHA1}\n"
                f"  SHA1 obtenu : {patched_sha1}\n"
                "Aucun fichier de sortie n'a été créé."
            )
        print("  [OK] la ROM construite correspond bit pour bit au résultat attendu")

        print("\n[5/5] Création et vérification de la copie patchée")
        output_path, output = create_numbered_output(
            rom_path,
            directory_fd,
            directory_info,
        )
        _active_output_path = output_path
        output = resources.enter_context(output)
        require_output_directory_unchanged(
            rom_path.parent,
            directory_info,
            directory_fd,
        )
        require_path_matches_open_file(output_path, output, directory_fd)
        print(
            "  [OK] premier nom disponible utilisé : "
            f"{terminal_safe_text(output_path)}"
        )

        try:
            require_output_directory_unchanged(
                rom_path.parent,
                directory_info,
                directory_fd,
            )
            require_path_matches_open_file(output_path, output, directory_fd)
            require_distinct_open_files(source, output)
            write_open_file(output, patched)
            require_path_matches_open_file(output_path, output, directory_fd)
            (
                written_md5,
                written_sha1,
                written_sha256,
                written_state,
            ) = hashes_from_open_file(output, ROM_SIZE)
            require_path_matches_open_file(output_path, output, directory_fd)
            require_open_file_state(output, written_state)
        except (OSError, PatcherError) as exc:
            raise PatcherError(
                "la copie créée n'a pas pu être vérifiée "
                f"({terminal_safe_text(exc)}).\n"
                f"Par sécurité, aucun fichier n'a été supprimé automatiquement : "
                f"{terminal_safe_text(output_path)}"
            ) from exc

        if (
            written_md5 != EXPECTED_PATCHED_MD5
            or written_sha1 != EXPECTED_PATCHED_SHA1
            or written_sha256 != patched_sha256
        ):
            raise PatcherError(
                "la copie créée ne correspond pas au résultat attendu.\n"
                "Par sécurité, elle n'a pas été supprimée automatiquement : "
                f"{terminal_safe_text(output_path)}"
            )

        (
            source_after_md5,
            source_after_sha1,
            source_after_sha256,
            source_after_state,
        ) = hashes_from_open_file(source, ROM_SIZE)
        require_path_matches_open_file(rom_path, source)
        require_open_file_state(source, source_after_state)
        if (
            source_after_md5 != source_md5
            or source_after_sha1 != source_sha1
            or source_after_sha256 != source_sha256
        ):
            raise PatcherError(
                "la ROM source a changé pendant l'exécution, probablement à cause "
                "d'un autre programme. La copie produite reste séparée."
            )
        print(f"  [OK] source inchangée, MD5 toujours {source_after_md5}")

        require_output_directory_unchanged(
            rom_path.parent,
            directory_info,
            directory_fd,
        )
        require_path_matches_open_file(output_path, output, directory_fd)
        (
            written_md5,
            written_sha1,
            written_sha256,
            written_state,
        ) = hashes_from_open_file(output, ROM_SIZE)
        require_path_matches_open_file(output_path, output, directory_fd)
        require_open_file_state(output, written_state)
        if (
            written_md5 != EXPECTED_PATCHED_MD5
            or written_sha1 != EXPECTED_PATCHED_SHA1
            or written_sha256 != patched_sha256
        ):
            raise PatcherError(
                "la copie a changé pendant le dernier contrôle. Elle n'a pas été "
                "supprimée automatiquement : "
                f"{terminal_safe_text(output_path)}"
            )
        print(f"  [OK] MD5 relu : {written_md5}")
        print(f"  [OK] SHA1 relu: {written_sha1}")
        print(f"  [OK] SHA256 relu: {written_sha256}")
        print("  [OK] chemin et identité du fichier de sortie inchangés")

    _active_output_path = None
    print("\n=== SUCCÈS ===")
    print("ROM patchée créée et vérifiée au moment de sa création :")
    print(terminal_safe_text(output_path))
    print("Bonne shasse !")
    return output_path


def show_program_information() -> None:
    print("Pokémon Version Émeraude FR — RTC+TIMER RNG Fix")
    print("=" * 53)
    print("\n--CRÉDITS--\n")
    print(
        "Correctif original anglais : MWisBest "
        "(https://www.pokecommunity.com/attachments/"
        "emerald-32-bit-rtc-timer-rng-fix-ips.81587/)"
    )
    print("Portage français : KleineDropje")
    print("\n--COMPATIBILITÉ--\n")
    print("Windows 10/11, macOS 10.15 ou ultérieur et Linux")
    print("Python 3.9 ou version ultérieure ; version encore maintenue recommandée")
    if sys.flags.isolated:
        print("Mode isolé de Python (-I) : actif")
    else:
        print(
            "Mode renforcé : utilisez l'option -I si l'environnement Python "
            "n'est pas fiable"
        )
    print("\n--FONCTIONNEMENT--\n")
    print(
        "Ce script identifie la ROM française à partir de sa taille et de ses "
        "empreintes, contrôle les zones concernées, applique le correctif à "
        "une copie et vérifie le résultat final. Il fonctionne entièrement "
        "hors ligne, ne requiert aucun fichier annexe et n'écrit pas dans la "
        "ROM source.\n"
    )
    print("=" * 53)


def run(rom_argument: str | None, show_information: bool = True) -> Path:
    if show_information:
        show_program_information()

    interactive_input = rom_argument is None
    if interactive_input:
        rom_argument = read_bounded_input(
            "Collez ou glissez ici le chemin de la ROM .gba, puis Entrée :\n> "
        )

    supplied_path = (
        clean_interactive_path(rom_argument)
        if interactive_input
        else clean_argument_path(rom_argument)
    )

    print("\n[1/5] Contrôle du fichier fourni")
    if supplied_path.suffix.lower() != ".gba":
        raise PatcherError(
            f"extension refusée : {supplied_path.suffix or '(aucune)'}. "
            "Seul un fichier .gba est accepté."
        )
    print("  [OK] extension .gba")

    rom_path, path_was_recovered = resolve_existing_path(supplied_path)
    if rom_path.suffix.lower() != ".gba":
        raise PatcherError(
            "le fichier réellement visé ne porte pas l'extension .gba."
        )
    if path_was_recovered:
        print("  [OK] caractère parasite corrigé automatiquement dans le chemin")
    print(f"  [OK] fichier source : {terminal_safe_text(rom_path)}")
    return patch_rom(rom_path)


def read_bounded_input(prompt: str) -> str:
    """Lit un chemin sans permettre à une ligne démesurée d'épuiser la mémoire."""
    print(prompt, end="", flush=True)
    try:
        line = sys.stdin.readline(MAX_INPUT_CHARACTERS + 2)
    except (OSError, ValueError) as exc:
        raise InputClosedError(
            "impossible de lire un chemin sur l'entrée standard."
        ) from exc
    if line == "":
        raise InputClosedError(
            "aucun chemin n'a été reçu sur l'entrée standard."
        )

    content = line.rstrip("\r\n")
    if len(content) > MAX_INPUT_CHARACTERS:
        try:
            while line and not line.endswith("\n"):
                line = sys.stdin.readline(MAX_INPUT_CHARACTERS + 2)
        except (OSError, ValueError):
            pass
        raise PatcherError(
            "chemin refusé : la saisie dépasse la limite de "
            f"{MAX_INPUT_CHARACTERS} caractères."
        )
    return content


def configure_standard_streams() -> None:
    """Préserve les messages si le terminal ne représente pas tout Unicode."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(errors="backslashreplace")
        except (OSError, ValueError):
            pass


def report_patcher_error(exc: PatcherError) -> None:
    sys.stdout.flush()
    print(
        f"\n[ERREUR] {terminal_safe_text(exc, preserve_newlines=True)}",
        file=sys.stderr,
        flush=True,
    )
    report_incomplete_output_if_any()


def report_incomplete_output_if_any() -> None:
    global _active_output_path
    if _active_output_path is None:
        return

    output_path = _active_output_path
    _active_output_path = None
    print(
        "[ATTENTION] Une sortie a été créée avant l'arrêt et peut être "
        "incomplète :\n"
        f"  {terminal_safe_text(output_path)}\n"
        "Ne l'utilisez pas sans la vérifier ou relancer correctement le patch.",
        file=sys.stderr,
        flush=True,
    )


def run_interactive() -> Path:
    first_attempt = True
    while True:
        try:
            return run(None, show_information=first_attempt)
        except InputClosedError:
            raise
        except PatcherError as exc:
            report_patcher_error(exc)
            print(
                "\nVous pouvez glisser ou coller un autre fichier. "
                "Pour quitter, utilisez Ctrl+C."
            )
            first_attempt = False


def main(argv: list[str] | None = None) -> int:
    configure_standard_streams()
    try:
        args = parse_arguments(argv)
        if args.rom is None:
            run_interactive()
        else:
            run(args.rom)
    except PatcherError as exc:
        report_patcher_error(exc)
        return 1
    except KeyboardInterrupt:
        sys.stdout.flush()
        print("\n[ANNULÉ] Opération interrompue par l'utilisateur.", file=sys.stderr)
        report_incomplete_output_if_any()
        return 130
    except OSError as exc:
        sys.stdout.flush()
        print(
            "\n[ERREUR] erreur système inattendue : "
            f"{terminal_safe_text(exc)}",
            file=sys.stderr,
        )
        report_incomplete_output_if_any()
        return 1
    except MemoryError:
        sys.stdout.flush()
        print("\n[ERREUR] mémoire disponible insuffisante.", file=sys.stderr)
        report_incomplete_output_if_any()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
