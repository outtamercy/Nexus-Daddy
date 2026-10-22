"""MO2 tool window for Nexus Daddy's encrypted key and permission list."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (QAbstractItemView, QDialog, QHBoxLayout, QLabel,
                             QFileDialog, QInputDialog, QLineEdit, QMessageBox, QPushButton, QTableWidget,
                             QTableWidgetItem, QVBoxLayout)

import mobase

from . import api


def requester_icon(name: str) -> QIcon | None:
    """Grab a requester's own icon when it bothered to ship one."""
    plugins_root = Path(__file__).parent.parent
    requested = name.casefold()
    for plugin_dir in plugins_root.iterdir():
        if not plugin_dir.is_dir() or plugin_dir.name.casefold() != requested:
            continue
        icon_path = plugin_dir / "icon.png"
        if icon_path.is_file():
            return QIcon(str(icon_path))
    return None


class NexusDaddyWindow(QDialog):
    def __init__(self, organizer):
        super().__init__()
        self.organizer = organizer
        self.store = api.vault(organizer)
        self.setWindowTitle("Nexus Daddy — Nexus API Companion")
        self.resize(760, 650)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Nexus Daddy uses MO2's Qt network stack and keeps TLS certificate verification on."))
        layout.addWidget(QLabel("Public v2 lookups need no key. A key is only handed to a plugin after you allow that plugin below."))
        self.state = QLabel()
        layout.addWidget(self.state)
        self.key_box = QLineEdit(self)
        self.key_box.setPlaceholderText("Paste a Nexus API key to store it with Windows DPAPI")
        self.key_box.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.key_box)
        key_actions = QHBoxLayout()
        save = QPushButton("Store key", self); save.clicked.connect(self.save_key)
        clear = QPushButton("Remove stored key", self); clear.clicked.connect(self.clear_key)
        test = QPushButton("Test public Nexus access", self); test.clicked.connect(self.test_public)
        key_actions.addWidget(save); key_actions.addWidget(clear); key_actions.addWidget(test); key_actions.addStretch(1)
        layout.addLayout(key_actions)
        layout.addWidget(QLabel("GitHub catalog token — separate from the Nexus key; only allowed plugins can ask for it."))
        self.github_box = QLineEdit(self)
        self.github_box.setPlaceholderText("Paste a fine-grained GitHub token limited to Package-Daddy-Catalog")
        self.github_box.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.github_box)
        github_actions = QHBoxLayout()
        save_github = QPushButton("Store GitHub token", self); save_github.clicked.connect(self.save_github_token)
        clear_github = QPushButton("Remove GitHub token", self); clear_github.clicked.connect(self.clear_github_token)
        github_actions.addWidget(save_github); github_actions.addWidget(clear_github); github_actions.addStretch(1)
        layout.addLayout(github_actions)
        self.github_oauth_client_box = QLineEdit(self)
        self.github_oauth_client_box.setPlaceholderText("GitHub App client ID (needed only for contributor sign-in)")
        self.github_oauth_client_box.setText(self.store.github_oauth_client_id)
        layout.addWidget(self.github_oauth_client_box)
        oauth_actions = QHBoxLayout()
        save_oauth = QPushButton("Save contributor login app ID", self); save_oauth.clicked.connect(self.save_github_oauth_client_id)
        clear_contributor = QPushButton("Disconnect contributor GitHub", self); clear_contributor.clicked.connect(self.clear_github_contributor_token)
        oauth_actions.addWidget(save_oauth); oauth_actions.addWidget(clear_contributor); oauth_actions.addStretch(1)
        layout.addLayout(oauth_actions)
        layout.addWidget(QLabel("Plugins that have asked for the stored key"))
        self.table = QTableWidget(0, 3, self)
        self.table.setHorizontalHeaderLabels(("Plugin", "Nexus key", "GitHub catalog"))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setColumnWidth(0, 185)
        self.table.setIconSize(QSize(112, 28))
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)
        permissions = QHBoxLayout()
        add_plugin = QPushButton("Add plugin…", self); add_plugin.clicked.connect(self.add_plugin)
        allow = QPushButton("Allow selected", self); allow.clicked.connect(lambda: self.set_selected(True))
        deny = QPushButton("Deny selected", self); deny.clicked.connect(lambda: self.set_selected(False))
        close = QPushButton("Close", self); close.clicked.connect(self.close)
        permissions.addWidget(add_plugin); permissions.addWidget(allow); permissions.addWidget(deny); permissions.addStretch(1); permissions.addWidget(close)
        layout.addLayout(permissions)
        self.refresh()

    def refresh(self):
        nexus_state = "Nexus key is locked up with Windows." if self.store.has_key else "No Nexus key stored. Public lookups still work fine."
        github_state = "GitHub catalog token is locked up with Windows." if self.store.has_github_token else "No GitHub catalog token stored."
        self.state.setText(nexus_state + " " + github_state)
        nexus_permissions = self.store.permissions()
        github_permissions = self.store.github_permissions()
        entries = sorted(set(nexus_permissions) | set(github_permissions), key=str.lower)
        self.table.setRowCount(len(entries))
        for row, name in enumerate(entries):
            plugin_item = QTableWidgetItem()
            plugin_item.setData(Qt.ItemDataRole.UserRole, name)
            icon = requester_icon(name)
            if icon is not None:
                plugin_item.setIcon(icon)
                plugin_item.setToolTip(name)
                self.table.setRowHeight(row, 34)
            else:
                plugin_item.setText(name)
            self.table.setItem(row, 0, plugin_item)
            self.table.setItem(row, 1, QTableWidgetItem("Allowed" if nexus_permissions.get(name) else "Denied / awaiting approval"))
            self.table.setItem(row, 2, QTableWidgetItem("Allowed" if github_permissions.get(name) else "Denied / awaiting approval"))

    def save_key(self):
        try:
            self.store.store(self.key_box.text())
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Nexus Daddy", str(exc))
            return
        self.key_box.clear()
        self.refresh()

    def clear_key(self):
        self.store.clear()
        self.refresh()

    def save_github_token(self):
        try:
            self.store.store_github_token(self.github_box.text())
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Nexus Daddy", str(exc))
            return
        self.github_box.clear()
        self.refresh()

    def clear_github_token(self):
        self.store.clear_github_token()
        self.refresh()

    def save_github_oauth_client_id(self):
        try:
            self.store.set_github_oauth_client_id(self.github_oauth_client_box.text())
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Nexus Daddy", str(exc))
            return
        self.refresh()

    def clear_github_contributor_token(self):
        self.store.clear_github_contributor_token()
        self.refresh()

    def set_selected(self, allowed: bool):
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        if item is None:
            QMessageBox.information(self, "Nexus Daddy", "Select a plugin first.")
            return
        name = item.data(Qt.ItemDataRole.UserRole) or item.text()
        if not isinstance(name, str) or not name:
            QMessageBox.warning(self, "Nexus Daddy", "That plugin row lost its permission name somehow. Pick it again.")
            return
        column = self.table.currentColumn()
        if column == 2:
            self.store.set_github_allowed(name, allowed)
        else:
            self.store.set_allowed(name, allowed)
        self.refresh()

    def add_plugin(self):
        """Put a local MO2 Python plugin in the permission list, denied first."""
        plugins_root = Path(__file__).parent.parent
        filename, _filter = QFileDialog.getOpenFileName(
            self,
            "Add an MO2 plugin to Nexus Daddy",
            str(plugins_root),
            "MO2 Python plugin (*.py)",
        )
        if not filename:
            return
        selected = Path(filename)
        if selected.suffix.casefold() != ".py" or not selected.is_file():
            QMessageBox.warning(self, "Nexus Daddy", "Pick a real local .py plugin file, not some random mystery blob.")
            return
        default_name = selected.stem
        requester, accepted = QInputDialog.getText(
            self,
            "Plugin permission name",
            "Permission name this plugin uses when it asks Nexus Daddy for access:\n"
            "(Usually its display/plugin name; it must match exactly.)",
            text=default_name,
        )
        requester = requester.strip()
        if not accepted or not requester:
            return
        # Adding never grants a secret.  It creates visible denied rows so the
        # user deliberately chooses Nexus and/or GitHub permission afterward.
        self.store.set_allowed(requester, False)
        self.store.set_github_allowed(requester, False)
        self.refresh()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None and item.data(Qt.ItemDataRole.UserRole) == requester:
                self.table.selectRow(row)
                break

    def test_public(self):
        try:
            game_id = api.NexusClient().game_id("skyrimspecialedition")
            QMessageBox.information(self, "Nexus Daddy", f"Public Nexus access is good. SSE game ID: {game_id}.")
        except (api.NexusDaddyError, ImportError) as exc:
            QMessageBox.warning(self, "Nexus Daddy", str(exc))


class NexusDaddyPlugin(mobase.IPluginTool):
    def __init__(self):
        super().__init__()
        self._organizer = None

    def init(self, organizer):
        self._organizer = organizer
        return True

    def name(self): return "NexusDaddy"
    def author(self): return "outtamercy"
    def description(self): return "A first-party, Qt-network Nexus companion for MO2 plugins."
    def version(self): return mobase.VersionInfo("2.0.0", mobase.VersionScheme.DISCOVER)
    def isActive(self): return True
    def settings(self): return []
    def displayName(self): return "Nexus Daddy"
    def tooltip(self): return "Manage Nexus Daddy's encrypted API key and plugin permissions"
    def icon(self): return QIcon(str(Path(__file__).with_name("icon.png")))
    def group(self): return mobase.PluginSettingGroup.Tools

    def display(self):
        if self._organizer is not None:
            NexusDaddyWindow(self._organizer).exec()
