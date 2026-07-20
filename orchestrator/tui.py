"""Interactive terminal user interface for the assessment workflow.

The interface intentionally uses only the Python standard library.  It is a
thin, reviewable front end around the existing command-line entry point: it
does not alter configuration files or execute a scan until the user confirms
the selected action.
"""

from __future__ import annotations

import curses
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class MenuItem:
    """An action displayed on the home screen."""

    label: str
    description: str
    action: str


MENU_ITEMS = (
    MenuItem("Setup prüfen", "Werkzeuge und Konfiguration ohne Scan prüfen", "validate"),
    MenuItem("Sichere Demo", "Erzeugt ausschließlich synthetische Testdaten", "demo"),
    MenuItem("Autorisierte Bewertung", "Netz erkennen und einen echten Scan starten", "assess"),
    MenuItem("Bericht anzeigen", "Pfad zum zuletzt erzeugten HTML-Bericht", "report"),
    MenuItem("Beenden", "Die Anwendung ohne Änderungen verlassen", "quit"),
)


def assessment_command(action: str, profile: str = "quick") -> list[str]:
    """Build a command for an action without involving a shell."""
    command = [sys.executable, str(PROJECT_ROOT / "run_assessment.py")]
    if action == "validate":
        return command + ["--auto-network", "--dry-run"]
    if action == "demo":
        return command + ["--mock", "--profile", "quick", "--no-delta"]
    if action == "assess":
        return command + ["--auto-network", "--profile", profile]
    raise ValueError(f"Unknown TUI action: {action}")


def tool_status() -> list[str]:
    """Return human-readable availability information for key prerequisites."""
    commands = ("python3", "nmap", "curl", "git")
    return [f"{name}: {'bereit' if shutil.which(name) else 'fehlt'}" for name in commands]


class AssessmentTUI:
    """Curses-based guided workflow for local, authorized assessments."""

    def __init__(self, screen: "curses._CursesWindow") -> None:
        self.screen = screen
        self.selected = 0

    def run(self) -> None:
        curses.curs_set(0)
        self.screen.keypad(True)
        while True:
            self._draw_home()
            key = self.screen.getch()
            if key in (curses.KEY_UP, ord("k")):
                self.selected = (self.selected - 1) % len(MENU_ITEMS)
            elif key in (curses.KEY_DOWN, ord("j")):
                self.selected = (self.selected + 1) % len(MENU_ITEMS)
            elif key in (10, 13, curses.KEY_ENTER):
                if not self._handle(MENU_ITEMS[self.selected].action):
                    return
            elif key in (ord("q"), 27):
                return

    def _draw_home(self) -> None:
        self.screen.erase()
        self._write(1, 2, "ESXi Stealth VA – Geführte Terminal-Oberfläche", curses.A_BOLD)
        self._write(3, 2, "Führe nur Bewertungen für Systeme aus, für die eine ausdrückliche Erlaubnis vorliegt.")
        self._write(5, 2, "Pfeiltasten: auswählen   Enter: öffnen   q: beenden", curses.A_DIM)
        for index, item in enumerate(MENU_ITEMS):
            y = 7 + index * 3
            style = curses.A_REVERSE if index == self.selected else curses.A_NORMAL
            self._write(y, 4, item.label, style | curses.A_BOLD)
            self._write(y + 1, 6, item.description, style)
        self.screen.refresh()

    def _handle(self, action: str) -> bool:
        if action == "quit":
            return False
        if action == "report":
            report = PROJECT_ROOT / "output" / "assessment_report.html"
            message = f"Bericht: {report}" if report.exists() else "Es wurde noch kein HTML-Bericht erzeugt."
            self._message("Bericht", [message])
            return True
        if action == "assess":
            self._assessment_flow()
            return True
        if action == "validate":
            self._confirm_and_run(
                "Setup prüfen",
                ["Es wird kein Scan gestartet.", *tool_status()],
                assessment_command(action),
            )
            return True
        self._confirm_and_run(
            "Sichere Demo",
            ["Die Demo verwendet nur künstliche Daten und kontaktiert keine Ziele."],
            assessment_command(action),
        )
        return True

    def _assessment_flow(self) -> None:
        profile = self._choose_profile()
        if profile is None:
            return
        lines = [
            "Die automatische Erkennung beschränkt sich auf private Netze.",
            "Der Scan kann Netzwerkverkehr und Sicherheitsalarme erzeugen.",
            f"Ausgewähltes Profil: {profile}",
            "",
            "Bestätigen Sie nur, wenn Sie für den gesamten erkannten Bereich autorisiert sind.",
        ]
        self._confirm_and_run("Autorisierung", lines, assessment_command("assess", profile))

    def _choose_profile(self) -> str | None:
        profiles = [
            ("quick", "wenig Traffic, guter erster Lauf"),
            ("standard", "ausgewogene Abdeckung"),
            ("thorough", "alle TCP-Ports; kann Stunden dauern"),
        ]
        index = 0
        while True:
            self.screen.erase()
            self._write(2, 2, "Scan-Profil auswählen", curses.A_BOLD)
            self._write(4, 2, "Pfeiltasten und Enter verwenden; Esc bricht ab.", curses.A_DIM)
            for number, (name, description) in enumerate(profiles):
                style = curses.A_REVERSE if number == index else curses.A_NORMAL
                self._write(6 + number * 2, 4, name, style | curses.A_BOLD)
                self._write(7 + number * 2, 6, description, style)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (curses.KEY_UP, ord("k")):
                index = (index - 1) % len(profiles)
            elif key in (curses.KEY_DOWN, ord("j")):
                index = (index + 1) % len(profiles)
            elif key in (10, 13, curses.KEY_ENTER):
                return profiles[index][0]
            elif key in (27, ord("q")):
                return None

    def _confirm_and_run(self, title: str, lines: Sequence[str], command: list[str]) -> None:
        self.screen.erase()
        self._write(2, 2, title, curses.A_BOLD)
        for index, line in enumerate(lines):
            self._write(4 + index, 2, line)
        self._write(6 + len(lines), 2, "Ausführen? [j/N]", curses.A_BOLD)
        self.screen.refresh()
        key = self.screen.getch()
        if key not in (ord("j"), ord("J"), ord("y"), ord("Y")):
            self._message(title, ["Abgebrochen. Es wurde nichts ausgeführt."])
            return
        curses.endwin()
        try:
            print("\nStarte:", " ".join(command), "\n")
            completed = subprocess.run(command, cwd=PROJECT_ROOT, check=False)
            input(f"\nVorgang mit Status {completed.returncode} beendet. Enter für das Menü …")
        finally:
            self.screen.refresh()

    def _message(self, title: str, lines: Sequence[str]) -> None:
        self.screen.erase()
        self._write(2, 2, title, curses.A_BOLD)
        for index, line in enumerate(lines):
            self._write(4 + index, 2, line)
        self._write(6 + len(lines), 2, "Enter drücken, um fortzufahren.", curses.A_DIM)
        self.screen.refresh()
        self.screen.getch()

    def _write(self, y: int, x: int, text: str, style: int = curses.A_NORMAL) -> None:
        height, width = self.screen.getmaxyx()
        if y < height:
            self.screen.addnstr(y, x, text, max(0, width - x - 1), style)


def launch() -> int:
    """Start the interactive interface, reporting a useful error outside a TTY."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Die interaktive Oberfläche benötigt ein Terminal (TTY).", file=sys.stderr)
        return 2
    curses.wrapper(lambda screen: AssessmentTUI(screen).run())
    return 0
