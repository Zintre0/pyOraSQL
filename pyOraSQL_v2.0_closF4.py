# oracle_connector.py - COMPLETE CONSOLIDATED VERSION WITH SECURITY FIXES
import os
import csv
import json as json_lib
import logging
import oracledb
import datetime
import subprocess
import shlex
import tempfile
import re
import io
import base64
import fcntl
import threading
import time
from pathlib import Path
from functools import lru_cache
from dotenv import load_dotenv

from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich import box
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.lexers import PygmentsLexer
from pygments.lexers.sql import SqlLexer
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import HTML, FormattedText

# ──────────────────────────────────────────────────────────────
# INITIAL SETUP
# ──────────────────────────────────────────────────────────────
load_dotenv()
console = Console()

def init_oracle_client():
	"""Initialize Oracle client with fallback to thin mode"""
	try:
		if os.getenv('ORA_SERVER_TYPE') == 'thin':
			console.print("[green]✓ Oracle Thin Mode[/green]")
			return "thin"
		
		try:
			oracledb.init_oracle_client()
			version = oracledb.clientversion()
			console.print(f"[green]✓ Oracle Thick Client v{version[0]}.{version[1]}[/green]")
			return "thick"
		except oracledb.Error as e:
			if "DPI-1047" in str(e):
				console.print("[yellow]⚠️  Falling back to Thin Mode[/yellow]")
				return "thin"
			else:
				raise
	except Exception as e:
		console.print(f"[bold red]Oracle Client Error: {e}[/bold red]")
		return "none"

CLIENT_MODE = init_oracle_client()

# Secure logging
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)
logging.basicConfig(
	filename=log_dir / "query_results.log",
	level=logging.INFO,
	format="%(asctime)s - %(levelname)s - %(message)s",
	encoding="utf-8"
)

# Create audit directory
audit_dir = Path("audit")
audit_dir.mkdir(exist_ok=True)

def json_serial(obj):
	if isinstance(obj, (datetime.datetime, datetime.date)):
		return obj.isoformat()
	raise TypeError(f"Type {type(obj)} not serializable")
# ──────────────────────────────────────────────────────────────
# SECURE ENCRYPTION SYSTEM (REPLACES BASE64)
# ──────────────────────────────────────────────────────────────
try:
	from cryptography.fernet import Fernet
	CRYPTO_AVAILABLE = True
except ImportError:
	console.print("[red]⚠️  cryptography module not installed![/red]")
	console.print("Run: pip install cryptography")
	CRYPTO_AVAILABLE = False

class SecureEncryption:
	_instance = None
	
	def __new__(cls):
		if cls._instance is None:
			cls._instance = super(SecureEncryption, cls).__new__(cls)
			cls._instance._initialize()
		return cls._instance
	
	def _initialize(self):
		key_file = Path(".audit_key")
		if not key_file.exists():
			key = Fernet.generate_key()
			key_file.write_bytes(key)
			try:
				key_file.chmod(0o600)  # Owner read/write only
			except:
				pass
			console.print("[green]✓ Generated new encryption key[/green]")
		self.key = key_file.read_bytes()
		self.cipher = Fernet(self.key)
	
	def encrypt(self, text):
		"""Securely encrypt text"""
		try:
			return self.cipher.encrypt(text.encode()).decode()
		except Exception as e:
			console.print(f"[red]Encryption error: {e}[/red]")
			raise
	
	def decrypt(self, text):
		"""Decrypt encrypted text"""
		try:
			return self.cipher.decrypt(text.encode()).decode()
		except Exception as e:
			console.print(f"[red]Decryption error: {e}[/red]")
			raise

# Global encryption instance
if CRYPTO_AVAILABLE:
	_encryption = SecureEncryption()
	
	def secure_encrypt(text):
		"""Public wrapper for secure encryption"""
		return _encryption.encrypt(text)
	
	def secure_decrypt(text):
		"""Public wrapper for secure decryption"""
		return _encryption.decrypt(text)
else:
	# Fallback with warning
	def secure_encrypt(text):
		console.print("[red]⚠️  INSECURE: cryptography module not installed![/red]")
		return base64.b64encode(text.encode()).decode()
	
	def secure_decrypt(text):
		try:
			return base64.b64decode(text.encode()).decode()
		except:
			return ""
# ──────────────────────────────────────────────────────────────
# APPLICATION STATE MANAGEMENT
# ──────────────────────────────────────────────────────────────
class ApplicationState:
	def __init__(self):
		self.connection = None
		self.current_profile = None
		self.formatter = OutputFormatter()
		self.last_result = None
		self.cache = None
		self.completer = None
		self.schema_snapshots = {}
		self.audit_registry = AuditRegistry()

	def update_connection(self, new_connection, profile_name):
		if self.connection:
			try:
				self.connection.close()
			except:
				pass
		
		self.connection = new_connection
		self.current_profile = profile_name
		self.last_result = None
		
		if new_connection:
			self.cache = MetadataCache(new_connection)
			self.completer = OracleCompleter(self.cache)
		else:
			self.cache = None
			self.completer = None

# ──────────────────────────────────────────────────────────────
# METADATA CACHE WITH TTL
# ──────────────────────────────────────────────────────────────
class MetadataCache:
	def __init__(self, conn):
		self.conn = conn
		self._tables = None
		self._objects = None
		self._columns = {}
		self._deps = {}
		self._cache_timestamps = {}
		self._cache_ttl = 300  # 5 minutes in seconds

	def _is_cache_valid(self, cache_key):
		"""Check if cache is still valid based on TTL"""
		if cache_key not in self._cache_timestamps:
			return False
		age = time.time() - self._cache_timestamps[cache_key]
		return age < self._cache_ttl

	@lru_cache(maxsize=256)
	def get_tables(self):
		if self._tables is None or not self._is_cache_valid('tables'):
			with self.conn.cursor() as cur:
				cur.execute("""
					SELECT table_name FROM user_tables 
					UNION SELECT view_name FROM user_views 
					ORDER BY 1
				""")
				self._tables = {r[0] for r in cur.fetchall()}
				self._cache_timestamps['tables'] = time.time()
		return self._tables

	@lru_cache(maxsize=512)
	def get_objects(self):
		if self._objects is None or not self._is_cache_valid('objects'):
			with self.conn.cursor() as cur:
				cur.execute("""
					SELECT object_name FROM user_objects 
					WHERE object_type NOT LIKE '%BODY%' 
					ORDER BY 1
				""")
				self._objects = {r[0] for r in cur.fetchall()}
				self._cache_timestamps['objects'] = time.time()
		return self._objects

	@lru_cache(maxsize=512)
	def get_columns(self, table):
		table = table.upper()
		cache_key = f"columns_{table}"
		
		if table not in self._columns or not self._is_cache_valid(cache_key):
			try:
				with self.conn.cursor() as cur:
					cur.execute("""
						SELECT column_name FROM user_tab_columns 
						WHERE table_name = :1 
						ORDER BY column_id
					""", [table])
					self._columns[table] = {r[0] for r in cur.fetchall()}
					self._cache_timestamps[cache_key] = time.time()
			except:
				self._columns[table] = set()
		return self._columns[table]

	def set_cache_ttl(self, seconds):
		"""Set cache time-to-live in seconds"""
		self._cache_ttl = seconds
		console.print(f"[green]Cache TTL set to {seconds} seconds[/green]")

	def invalidate_cache(self, cache_type=None):
		"""Invalidate cache completely or for specific type"""
		if cache_type is None:
			self._tables = None
			self._objects = None
			self._columns.clear()
			self._deps.clear()
			self._cache_timestamps.clear()
			self.get_tables.cache_clear()
			self.get_objects.cache_clear()
			self.get_columns.cache_clear()
			console.print("[green]Cache completely invalidated[/green]")
		elif cache_type == 'tables':
			self._tables = None
			self._cache_timestamps.pop('tables', None)
			self.get_tables.cache_clear()
			console.print("[green]Table cache invalidated[/green]")
		elif cache_type == 'objects':
			self._objects = None
			self._cache_timestamps.pop('objects', None)
			self.get_objects.cache_clear()
			console.print("[green]Object cache invalidated[/green]")
		elif cache_type == 'columns':
			self._columns.clear()
			for key in list(self._cache_timestamps.keys()):
				if key.startswith('columns_'):
					self._cache_timestamps.pop(key, None)
			self.get_columns.cache_clear()
			console.print("[green]Column cache invalidated[/green]")
# ──────────────────────────────────────────────────────────────
# CONNECTION WRAPPER
# ──────────────────────────────────────────────────────────────
class ConnectionWrapper:
	"""Wrapper for Oracle connections to ensure proper cleanup"""
	def __init__(self, connection, schema_name):
		self._connection = connection
		self.schema_name = schema_name
		self._closed = False
	
	def __enter__(self):
		return self._connection
	
	def __exit__(self, exc_type, exc_val, exc_tb):
		self.close()
	
	def close(self):
		if not self._closed and self._connection:
			try:
				self._connection.close()
				self._closed = True
			except:
				pass
	
	def __getattr__(self, name):
		return getattr(self._connection, name)
	
	def __del__(self):
		self.close()

# ──────────────────────────────────────────────────────────────
# CONNECTION MANAGEMENT
# ──────────────────────────────────────────────────────────────
def load_connections():
	# Try loading new format first
	nf_config_path = Path("connectionNF.json")
	if nf_config_path.exists():
		try:
			with open(nf_config_path, "r", encoding="utf-8") as f:
				nf_data = json_lib.load(f)
			
			connections = {}
			for env_name, env_data in nf_data.items():
				server = env_data.get("server", {})
				address = server.get("address")
				port = server.get("port", 1521)
				
				# Build a robust TNS descriptor
				if "service_name" in server:
					dsn_base = f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={address})(PORT={port}))(CONNECT_DATA=(SERVICE_NAME={server['service_name']})))"
				elif "sid" in server:
					dsn_base = f"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={address})(PORT={port}))(CONNECT_DATA=(SID={server['sid']})))"
				else:
					# Fallback to EZConnect if neither is specified
					dsn_base = address
				
				for acc in env_data.get("accounts", []):
					user = acc.get("user")
					password = acc.get("pass")
					if user and password:
						# Create a profile name: ENV_USER
						profile_name = f"{env_name}_{user}"
						connections[profile_name] = {
							"user": user,
							"password": password,
							"dsn": dsn_base
						}
			
			console.print(f"[green]✓ Loaded {len(connections)} profiles from connectionNF.json[/green]")
			return connections
		except Exception as e:
			console.print(f"[red]Failed to load connectionNF.json: {e}[/red]")
			# Fallthrough to old file

	config_path = Path("connections.json")
	if not config_path.exists():
		console.print("[bold red]connections.json not found![/bold red]")
		console.print("   Create it with this structure:")
		console.print("""
   {
     "dev": {
       "user": "your_username",
       "password": "your_password", 
       "dsn": "hostname:port/service_name"
     }
   }""")
		return {}
	try:
		with open(config_path, "r", encoding="utf-8") as f:
			data = json_lib.load(f)
			console.print(f"[green]✓ Loaded {len(data)} connection profile(s)[/green]")
			return data if isinstance(data, dict) else {}
	except Exception as e:
		console.print(f"[red]Failed to load connections.json: {e}[/red]")
		return {}

def check_connection_health(connection):
	if connection is None:
		return False, "No database connection established"
	try:
		with connection.cursor() as cursor:
			cursor.execute("SELECT 1 FROM DUAL")
			return True, "Connection healthy"
	except oracledb.Error as e:
		return False, f"Connection error: {e}"

def switch_connection(profile_name, connections, current_state):
	if profile_name not in connections:
		console.print(f"[red]Profile '{profile_name}' not found.[/red]")
		return current_state
	
	profile = connections[profile_name]
	console.print(f"[dim]Connecting to {profile_name} ({profile['dsn']})...[/dim]")
	try:
		new_conn = oracledb.connect(
			user=profile["user"],
			password=profile["password"],
			dsn=profile["dsn"]
		)
		current_state.update_connection(new_conn, profile_name)
		console.print(f"[bold green]Connected → {profile_name} ({profile['user']}@{profile['dsn']})[/bold green]")
		return current_state
	except oracledb.Error as e:
		console.print(f"[bold red]Connection failed: {e}[/bold red]")
		return current_state
# ──────────────────────────────────────────────────────────────
# AUDIT REGISTRY SYSTEM WITH SECURE ENCRYPTION
# ──────────────────────────────────────────────────────────────
class AuditRegistry:
	"""Manages schema audit monitoring registry with secure connections"""
	
	def __init__(self):
		self.registry_file = audit_dir / "registry.json"
		self.global_status_file = audit_dir / "global_status.json"
		self._file_lock = threading.RLock()
		self.registry = self._load_registry()
		self.global_status = self._load_global_status()
	
	def _lock_file(self, filepath, mode='r'):
		"""Context manager for file locking"""
		class FileLockContext:
			def __init__(self, filepath, mode):
				self.filepath = filepath
				self.mode = mode
				self.file = None
			
			def __enter__(self):
				self.file = open(self.filepath, self.mode, encoding='utf-8')
				if hasattr(fcntl, 'LOCK_EX') and 'w' in self.mode:
					fcntl.flock(self.file, fcntl.LOCK_EX)
				elif hasattr(fcntl, 'LOCK_SH'):
					fcntl.flock(self.file, fcntl.LOCK_SH)
				return self.file
			
			def __exit__(self, exc_type, exc_val, exc_tb):
				if self.file:
					if hasattr(fcntl, 'LOCK_UN'):
						fcntl.flock(self.file, fcntl.LOCK_UN)
					self.file.close()
		
		return FileLockContext(filepath, mode)

	def _load_registry(self):
		"""Load or create registry with file locking"""
		if not self.registry_file.exists():
			default = {
				"schemas": {},
				"version": "2.0",
				"created": datetime.datetime.now().isoformat(),
				"encryption": "fernet" if CRYPTO_AVAILABLE else "base64"
			}
			self._save_registry(default)
			return default
		try:
			with self._lock_file(self.registry_file, 'r'):
				with open(self.registry_file, 'r', encoding='utf-8') as f:
					data = json_lib.load(f)
					
					# Migration from old base64 "encryption"
					if data.get("version", "1.0") == "1.0":
						data = self._migrate_v1_to_v2(data)
					
					return data
		except Exception as e:
			console.print(f"[red]Failed to load registry: {e}[/red]")
			return {"schemas": {}, "version": "2.0"}
	
	def _migrate_v1_to_v2(self, old_data):
		"""Migrate from v1 (base64) to v2 (Fernet)"""
		console.print("[yellow]⚠️  Migrating audit registry from v1 to v2...[/yellow]")
		
		for schema_name, schema_info in old_data.get("schemas", {}).items():
			if "password_encrypted" in schema_info:
				try:
					# Try to decrypt old base64
					old_password = base64.b64decode(schema_info["password_encrypted"].encode()).decode()
					# Re-encrypt with new system
					schema_info["password_encrypted"] = secure_encrypt(old_password)
				except:
					console.print(f"[red]Failed to migrate password for {schema_name}[/red]")
					schema_info["password_encrypted"] = ""
		
		old_data["version"] = "2.0"
		old_data["encryption"] = "fernet" if CRYPTO_AVAILABLE else "base64"
		self._save_registry(old_data)
		console.print("[green]✓ Migration complete[/green]")
		return old_data
	
	def _save_registry(self, data=None):
		"""Save registry to file with locking"""
		data = data or self.registry
		try:
			with self._lock_file(self.registry_file, 'w'):
				with open(self.registry_file, 'w', encoding='utf-8') as f:
					json_lib.dump(data, f, indent=2, default=json_serial)
		except Exception as e:
			console.print(f"[red]Failed to save registry: {e}[/red]")
	
	def _load_global_status(self):
		"""Load or create global status"""
		if not self.global_status_file.exists():
			default = {
				"audit_enabled": False,
				"last_global_snapshot": None,
				"monitored_schemas": [],
				"total_snapshots": 0,
				"last_alert": None
			}
			self._save_global_status(default)
			return default
		try:
			with self._lock_file(self.global_status_file, 'r'):
				with open(self.global_status_file, 'r', encoding='utf-8') as f:
					return json_lib.load(f)
		except:
			return {"audit_enabled": False}
	
	def _save_global_status(self, data=None):
		"""Save global status to file"""
		data = data or self.global_status
		try:
			with self._lock_file(self.global_status_file, 'w'):
				with open(self.global_status_file, 'w', encoding='utf-8') as f:
					json_lib.dump(data, f, indent=2, default=json_serial)
		except Exception as e:
			console.print(f"[red]Failed to save global status: {e}[/red]")
	
	def add_schema(self, schema_name, user, password, dsn, enabled=True):
		"""Add a schema to audit monitoring with validation"""
		# Input validation
		if not schema_name or not user or not password or not dsn:
			console.print("[red]All fields are required[/red]")
			return False
		
		if schema_name in self.registry["schemas"]:
			console.print(f"[yellow]Schema '{schema_name}' already in registry[/yellow]")
			return False
		
		# Sanitize inputs
		schema_name = schema_name.strip().upper()
		user = user.strip()
		dsn = dsn.strip()
		
		self.registry["schemas"][schema_name] = {
			"user": user,
			"password_encrypted": secure_encrypt(password),
			"dsn": dsn,
			"enabled": enabled,
			"added_date": datetime.datetime.now().isoformat(),
			"last_snapshot": None,
			"snapshot_count": 0,
			"last_change": None
		}
		
		# Update global status
		if schema_name not in self.global_status.get("monitored_schemas", []):
			self.global_status.setdefault("monitored_schemas", []).append(schema_name)
		
		self._save_registry()
		self._save_global_status()
		console.print(f"[green]✓ Schema '{schema_name}' added to audit monitoring[/green]")
		return True
	
	def remove_schema(self, schema_name):
		"""Remove schema from audit monitoring"""
		if schema_name not in self.registry.get("schemas", {}):
			console.print(f"[red]Schema '{schema_name}' not found in registry[/red]")
			return False
		
		del self.registry["schemas"][schema_name]
		
		# Update global status
		if schema_name in self.global_status.get("monitored_schemas", []):
			self.global_status["monitored_schemas"].remove(schema_name)
		
		self._save_registry()
		self._save_global_status()
		console.print(f"[green]✓ Schema '{schema_name}' removed from audit monitoring[/green]")
		return True
	
	def list_schemas(self):
		"""List all monitored schemas"""
		schemas = self.registry.get("schemas", {})
		if not schemas:
			console.print("[yellow]No schemas in audit registry[/yellow]")
			return []
		
		table = Table(title="Audit Monitored Schemas")
		table.add_column("Schema", style="cyan")
		table.add_column("User", style="dim")
		table.add_column("DSN", style="dim")
		table.add_column("Enabled", style="green")
		table.add_column("Last Snapshot", style="dim")
		table.add_column("Snapshots", justify="right")
		
		for name, info in schemas.items():
			enabled = "✓" if info.get("enabled", False) else "✗"
			last_snap = info.get("last_snapshot", "Never")
			if last_snap and len(last_snap) > 20:
				last_snap = last_snap[:17] + "..."
			snapshot_count = info.get("snapshot_count", 0)
			
			table.add_row(
				name,
				info.get("user", "N/A"),
				info.get("dsn", "N/A")[:30],
				enabled,
				last_snap,
				str(snapshot_count)
			)
		
		console.print(table)
		return list(schemas.keys())
	
	def get_schema_connection(self, schema_name, max_retries=2):
		"""Get connection for a monitored schema with error handling"""
		if schema_name not in self.registry.get("schemas", {}):
			console.print(f"[red]Schema '{schema_name}' not in registry[/red]")
			return None
		
		schema_info = self.registry["schemas"][schema_name]
		if not schema_info.get("enabled", False):
			console.print(f"[yellow]Schema '{schema_name}' is disabled[/yellow]")
			return None
		
		conn = None
		last_error = None
		
		for attempt in range(max_retries):
			try:
				password = secure_decrypt(schema_info["password_encrypted"])
				conn = oracledb.connect(
					user=schema_info["user"],
					password=password,
					dsn=schema_info["dsn"]
				)
				
				# Test connection
				with conn.cursor() as cursor:
					cursor.execute("SELECT 1 FROM DUAL")
				
				console.print(f"[dim]Connected to '{schema_name}'[/dim]")
				return ConnectionWrapper(conn, schema_name)
				
			except oracledb.Error as e:
				last_error = e
				if attempt < max_retries - 1:
					console.print(f"[yellow]Retry {attempt + 1}/{max_retries} for '{schema_name}'[/yellow]")
					time.sleep(1)
				continue
			except Exception as e:
				console.print(f"[red]Unexpected error connecting to '{schema_name}': {e}[/red]")
				return None
		
		console.print(f"[red]Failed to connect to '{schema_name}' after {max_retries} attempts: {last_error}[/red]")
		return None
	
	def update_schema_status(self, schema_name, snapshot_name=None, change_detected=False):
		"""Update schema status after snapshot"""
		if schema_name not in self.registry.get("schemas", {}):
			return False
		
		now = datetime.datetime.now().isoformat()
		self.registry["schemas"][schema_name]["last_snapshot"] = now
		
		if snapshot_name:
			self.registry["schemas"][schema_name]["snapshot_count"] = \
				self.registry["schemas"][schema_name].get("snapshot_count", 0) + 1
		
		if change_detected:
			self.registry["schemas"][schema_name]["last_change"] = now
		
		# Update global status
		self.global_status["last_global_snapshot"] = now
		self.global_status["total_snapshots"] = \
			self.global_status.get("total_snapshots", 0) + 1
		
		if change_detected:
			self.global_status["last_alert"] = {
				"schema": schema_name,
				"timestamp": now,
				"type": "change_detected"
			}
		
		self._save_registry()
		self._save_global_status()
		return True
	
	def get_global_status(self):
		"""Get global audit status"""
		return self.global_status
# ──────────────────────────────────────────────────────────────
# AUTOCOMPLETE SYSTEM
# ──────────────────────────────────────────────────────────────
class OracleCompleter(Completer):
	KEYWORDS = {
		"SELECT","FROM","WHERE","INSERT","UPDATE","DELETE","CREATE",
		"ALTER","DROP","JOIN","INNER","LEFT","RIGHT","ON","AND","OR",
		"ORDER","BY","GROUP","HAVING","UNION","DISTINCT","INTO","VALUES",
		"SET","TABLE","VIEW","PACKAGE","FUNCTION","PROCEDURE"
	}

	def __init__(self, cache):
		self.cache = cache

	def get_completions(self, document: Document, complete_event):
		text = document.text_before_cursor.upper()
		word = document.get_word_before_cursor(WORD=True).upper()

		# Keywords
		if not any(k in text for k in ("FROM ", "JOIN ", "WHERE ", "AND ", "ON ")):
			for kw in self.KEYWORDS:
				if kw.startswith(word):
					yield Completion(kw, -len(word))

		# Tables after FROM/JOIN
		if re.search(r"\bFROM\s+\w*$|\bJOIN\s+\w*$", text):
			for t in self.cache.get_tables():
				if t.startswith(word):
					yield Completion(t, -len(word))

		# Columns after WHERE/AND/ON
		if re.search(r"\b(WHERE|AND|ON)\s+.*\w*$", text):
			tables = re.findall(r"FROM\s+([A-Z_]+)|JOIN\s+([A-Z_]+)", text)
			tables = {t for pair in tables for t in pair if t}
			for t in tables:
				for c in self.cache.get_columns(t):
					if c.startswith(word):
						yield Completion(c, -len(word), display=f"{c} ← {t}")

		# General objects
		for obj in self.cache.get_objects():
			if obj.startswith(word):
				yield Completion(obj, -len(word))

# ──────────────────────────────────────────────────────────────
# OUTPUT FORMATTER
# ──────────────────────────────────────────────────────────────
class OutputFormatter:
	def __init__(self):
		self.format = "table"

	def set_format(self, fmt):
		fmt = fmt.lower()
		if fmt not in {"table", "vertical", "json", "csv"}:
			console.print(f"[red]Invalid format: {fmt}[/red]")
			return False
		self.format = fmt
		console.print(f"[green]Output format → {fmt}[/green]")
		return True

	def display(self, result):
		if not result.rows:
			console.print("[yellow]No rows returned.[/yellow]")
			return

		visible_headers = result.get_visible_headers()
		visible_indices = result.get_visible_indices()
		data = [[row[i] for i in visible_indices] for row in result.rows]

		if self.format == "table":
			table = Table(title="Query Results", box=box.ROUNDED)
			for h in visible_headers:
				table.add_column(h, style="cyan", max_width=80)
			for row in data:
				safe_row = ["NULL" if c is None else (str(c)[:1000] + "…[TRUNCATED]" if len(str(c)) > 1000 else str(c)) for c in row]
				table.add_row(*safe_row)
			console.print(table)

		elif self.format == "vertical":
			for idx, row in enumerate(data, 1):
				console.print(f"[bold]**************** {idx}. row ****************[/bold]")
				for h, v in zip(visible_headers, row):
					val = "NULL" if v is None else str(v)
					console.print(f"[cyan]{h:<30}[/cyan] {val}")
				console.print()

		elif self.format == "json":
			json_data = [dict(zip(visible_headers, row)) for row in data]
			console.print(json_lib.dumps(json_data, indent=2, default=json_serial, ensure_ascii=False))

		elif self.format == "csv":
			output = io.StringIO()
			writer = csv.writer(output)
			writer.writerow(visible_headers)
			writer.writerows([[c if c is not None else "" for c in row] for row in data])
			console.print(output.getvalue())

class QueryResult:
	def __init__(self, headers, rows):
		self.original_headers = [h.upper() for h in headers]
		self.rows = rows
		self.hidden_columns = set()

	def get_visible_headers(self):
		return [h for h in self.original_headers if h not in self.hidden_columns]

	def get_visible_indices(self):
		return [i for i, h in enumerate(self.original_headers) if h not in self.hidden_columns]

	def show_columns(self):
		visible = self.get_visible_headers()
		total = len(self.original_headers)
		console.print(f"\n[bold]Columns ({len(visible)}/{total} visible):[/bold]")
		for i, col in enumerate(self.original_headers, 1):
			status = "[green]✓[/green]" if col in visible else "[red]✗[/red]"
			console.print(f"  {status} {i:3}. {col}")
		if self.hidden_columns:
			console.print(f"\n[red]Hidden:[/red] {', '.join(sorted(self.hidden_columns))}")

def execute_sql(connection, sql_query, formatter):
	try:
		with connection.cursor() as cursor:
			cursor.execute(sql_query)
			if cursor.description:
				headers = [desc[0] for desc in cursor.description]
				rows = cursor.fetchall()
				result = QueryResult(headers, rows)
				formatter.display(result)
				logging.info(f"SELECT SUCCESS: {sql_query[:200]}")
				return result
			else:
				console.print(f"[green]Success:[/green] {cursor.rowcount} row(s) affected")
				connection.commit()
				logging.info(f"DML/DDL SUCCESS: {sql_query[:200]}")
				return None
	except oracledb.Error as e:
		console.print(f"[bold red]Oracle Error:[/bold red] {e}")
		logging.error(f"SQL FAILED: {sql_query[:200]} | Error: {e}")
		return None
# ──────────────────────────────────────────────────────────────
# SCHEMA COMMANDS
# ──────────────────────────────────────────────────────────────
_TABLES_QUERY = "SELECT table_name FROM user_tables UNION SELECT view_name FROM user_views ORDER BY 1"

def cmd_tables(connection):
	with connection.cursor() as cursor:
		cursor.execute(_TABLES_QUERY)
		tables = [row[0] for row in cursor.fetchall()]
		if not tables:
			console.print("[yellow]No tables/views found in your schema.[/yellow]")
			return
		console.print(f"\n[bold]Found {len(tables)} table(s):[/bold]\n")
		line = ""
		for i, tbl in enumerate(tables, 1):
			item = f"{i:3}. {tbl}"
			if len(line) + len(item) > console.width - 15:
				console.print(line)
				line = ""
			line += item + "   "
		if line:
			console.print(line)
		console.print()

def cmd_describe(connection, obj_name):
	obj_name = obj_name.upper()
	with connection.cursor() as cursor:
		cursor.execute("""
			SELECT owner, object_name, object_type
			FROM all_objects
			WHERE object_name = :1 AND owner = USER
		""", [obj_name])
		obj = cursor.fetchone()
		if not obj:
			console.print(f"[red]Object '{obj_name}' not found.[/red]")
			return
		owner, _, obj_type = obj

		if obj_type in ("TABLE", "VIEW", "MATERIALIZED VIEW"):
			cursor.execute("""
				SELECT column_name, data_type, data_length, data_precision, data_scale,
					   nullable, char_length
				FROM all_tab_columns
				WHERE table_name = :1 AND owner = :2
				ORDER BY column_id
			""", [obj_name, owner])
			cols = cursor.fetchall()
			table = Table(title=f"{owner}.{obj_name} ({obj_type})", box=box.ROUNDED)
			table.add_column("Column", style="cyan")
			table.add_column("Type", style="green")
			table.add_column("Length", justify="right")
			table.add_column("Null?", style="yellow")
			for col in cols:
				name, dtype, dlen, prec, scale, null_, clen = col
				if dtype in ("CHAR", "VARCHAR2", "NVARCHAR2"):
					length = str(clen or dlen)
				elif dtype == "NUMBER":
					length = "-" if prec is None else f"{prec},{scale}" if scale else str(prec)
				else:
					length = str(dlen) if dlen else "-"
				null_text = "YES" if null_ == "Y" else "NO"
				table.add_row(name, dtype, length, null_text)
			console.print(table)
		else:
			console.print(f"[dim]{obj_type} — no columns to display[/dim]")

def cmd_src(connection, obj_name):
	obj_name = obj_name.upper()
	with connection.cursor() as cursor:
		cursor.execute("""
			SELECT type, line, text FROM all_source
			WHERE owner = USER AND name = :1
			ORDER BY type, line
		""", [obj_name])
		rows = cursor.fetchall()
		if not rows:
			console.print(f"[red]Source not found for '{obj_name}'[/red]")
			return
		obj_type = rows[0][0]
		console.print(f"\n[bold cyan]{obj_type} {obj_name}[/bold cyan]\n")
		for _, line_num, text in rows:
			console.print(f"{line_num:4} {text.rstrip() if text else ''}")

def cmd_view(connection, obj_name):
	obj_name = obj_name.upper()
	with connection.cursor() as cursor:
		cursor.execute("SELECT text FROM all_source WHERE owner = USER AND name = :1 ORDER BY line", [obj_name])
		source = "".join(row[0] or "" for row in cursor.fetchall())
		if not source.strip():
			console.print(f"[red]No source for '{obj_name}'[/red]")
			return
		with tempfile.NamedTemporaryFile(mode='w', suffix='.sql', delete=False, encoding='utf-8') as f:
			f.write(f"-- Source of {obj_name} @ {datetime.datetime.now():%Y-%m-%d %H:%M}\n\n{source}")
			tmp_path = f.name
		editor = os.getenv("EDITOR", "vim")
		try:
			subprocess.run(shlex.split(editor) + [tmp_path], check=True)
		except Exception:
			console.print("[yellow]Opening with less...[/yellow]")
			subprocess.run(["less", tmp_path], check=False)
		finally:
			try:
				Path(tmp_path).unlink()
			except:
				pass
# ──────────────────────────────────────────────────────────────
# PHASE 2: ENHANCED DEPENDENCY GRAPHS
# ──────────────────────────────────────────────────────────────
def draw_dependency_graph(connection, root_obj):
	"""Enhanced ASCII dependency graph"""
	root_obj = root_obj.upper()
	with connection.cursor() as cursor:
		cursor.execute("""
			SELECT referenced_owner||'.'||referenced_name AS ref, name AS obj 
			FROM all_dependencies WHERE owner = USER
			UNION
			SELECT name AS ref, referenced_owner||'.'||referenced_name AS obj 
			FROM all_dependencies WHERE referenced_owner = USER
		""")
		all_edges = cursor.fetchall()

	callers = {edge[1] for edge in all_edges if edge[0] == root_obj}
	callees = {edge[0] for edge in all_edges if edge[1] == root_obj}
	
	graph = Text()
	graph.append(f"\n[bold magenta]Dependency Graph: {root_obj}[/bold magenta]\n\n")
	graph.append(f"\t\t[bold cyan]{root_obj}[/bold cyan]\n")
	graph.append("\t\t│\n")
	
	if callers:
		graph.append("\t\t├── [green]↑ Called By[/green]\n")
		for i, caller in enumerate(sorted(callers)):
			prefix = "\t\t│   └── " if i == len(callers)-1 else "\t\t│   ├── "
			graph.append(f"{prefix}[green]{caller}[/green]\n")
	
	if callees:
		graph.append("\t\t└── [yellow]↓ Depends On[/yellow]\n")
		for i, callee in enumerate(sorted(callees)):
			prefix = "\t\t    └── " if i == len(callees)-1 else "\t\t    ├── "
			graph.append(f"\t\t{prefix}[yellow]{callee}[/yellow]\n")
	
	console.print(graph)

def draw_dependency_tree(connection, root_obj):
	"""Tree view dependencies"""
	root_obj = root_obj.upper()
	
	def build_tree(obj_name, depth=0, visited=None):
		if visited is None:
			visited = set()
		if obj_name in visited or depth > 5:
			return None
		visited.add(obj_name)
		
		with connection.cursor() as cursor:
			cursor.execute("""
				SELECT name, referenced_name, referenced_type 
				FROM all_dependencies 
				WHERE owner = USER AND name = :1
			""", [obj_name])
			deps = cursor.fetchall()
		
		if not deps:
			return None
			
		tree = Tree(f"[cyan]{obj_name}[/cyan]")
		for dep in deps:
			child_tree = build_tree(dep[1], depth + 1, visited)
			if child_tree:
				tree.add(child_tree)
			else:
				tree.add(f"[dim]{dep[1]} ({dep[2]})[/dim]")
		return tree
	
	tree = build_tree(root_obj)
	if tree:
		console.print(f"\n[bold magenta]Dependency Tree: {root_obj}[/bold magenta]")
		console.print(tree)
	else:
		console.print(f"[dim]No dependencies found for {root_obj}[/dim]")

def interactive_deps_explorer(connection, start_obj):
	current = start_obj.upper()
	history = [current]

	while True:
		console.print(f"\n[bold magenta]Dependency Explorer → {current}[/bold magenta]")
		draw_dependency_graph(connection, current)

		with connection.cursor() as cursor:
			cursor.execute("SELECT referenced_owner||'.'||referenced_name, referenced_type FROM all_dependencies WHERE name = :1 AND owner = USER", [current])
			callers = cursor.fetchall()
			cursor.execute("SELECT owner||'.'||name, type FROM all_dependencies WHERE referenced_name = :1 AND referenced_owner = USER", [current])
			callees = cursor.fetchall()

		all_deps = [(n, t) for n, t in callers] + [(n, t) for n, t in callees]
		if all_deps:
			console.print("\n[bold]Dependencies:[/bold]")
			for i, (name, typ) in enumerate(all_deps, 1):
				direction = "↑ (calls this)" if name in [c[0] for c in callers] else "↓ (this calls)"
				console.print(f"  {i:2}. [cyan]{name}[/cyan] — {direction} ({typ})")

		console.print("\n[bold]Commands:[/bold] number | name | src | desc | back | q")
		choice = console.input("[blue]→ [/blue]").strip()

		if choice.lower() in {'q', 'quit', 'exit'}:
			console.print("[dim]Goodbye from dependency explorer.[/dim]")
			break
		if choice.lower() in {'back', '..'}:
			if len(history) > 1:
				history.pop()
				current = history[-1]
			continue
		if choice.lower() == 'src':
			cmd_src(connection, current)
			continue
		if choice.lower() in {'desc', 'describe'}:
			cmd_describe(connection, current)
			continue

		try:
			idx = int(choice) - 1
			if 0 <= idx < len(all_deps):
				current = all_deps[idx][0]
				history.append(current)
				continue
		except:
			pass

		matches = [n for n, _ in all_deps if choice.upper() in n]
		if len(matches) == 1:
			current = matches[0]
			history.append(current)
		elif len(matches) > 1:
			console.print(f"[yellow]Multiple matches:[/yellow] {', '.join(matches[:10])}")
		else:
			console.print(f"[red]Not found:[/red] {choice}")

# ──────────────────────────────────────────────────────────────
# PHASE 2: SCHEMA COMPARISON TOOLS
# ──────────────────────────────────────────────────────────────
def take_schema_snapshot(connection, snapshot_name, state):
	"""Take snapshot of current schema"""
	snapshot = {
		'timestamp': datetime.datetime.now().isoformat(),
		'tables': {},
		'objects': {}
	}
	
	with connection.cursor() as cursor:
		cursor.execute("""
			SELECT table_name, column_name, data_type 
			FROM user_tab_columns 
			ORDER BY table_name, column_id
		""")
		for table, column, dtype in cursor.fetchall():
			if table not in snapshot['tables']:
				snapshot['tables'][table] = []
			snapshot['tables'][table].append(f"{column} ({dtype})")
		
		cursor.execute("SELECT object_name, object_type FROM user_objects")
		snapshot['objects'] = {row[0]: row[1] for row in cursor.fetchall()}
	
	state.schema_snapshots[snapshot_name] = snapshot
	console.print(f"[green]Snapshot '{snapshot_name}' saved with {len(snapshot['tables'])} tables[/green]")
	return state

def compare_schemas(state, snapshot1, snapshot2):
	"""Compare two schema snapshots"""
	if snapshot1 not in state.schema_snapshots:
		console.print(f"[red]Snapshot '{snapshot1}' not found[/red]")
		return
	if snapshot2 not in state.schema_snapshots:
		console.print(f"[red]Snapshot '{snapshot2}' not found[/red]")
		return
	
	snap1 = state.schema_snapshots[snapshot1]
	snap2 = state.schema_snapshots[snapshot2]
	
	table = Table(title=f"Schema Comparison: {snapshot1} vs {snapshot2}")
	table.add_column("Object Type", style="cyan")
	table.add_column(f"Only in {snapshot1}", style="red")
	table.add_column(f"Only in {snapshot2}", style="green")
	table.add_column("Common", style="yellow")
	
	tables1 = set(snap1['tables'].keys())
	tables2 = set(snap2['tables'].keys())
	
	table.add_row(
		"Tables",
		"\n".join(tables1 - tables2),
		"\n".join(tables2 - tables1), 
		f"{len(tables1 & tables2)} tables"
	)
	
	objs1 = set(snap1['objects'].keys())
	objs2 = set(snap2['objects'].keys())
	
	table.add_row(
		"Objects", 
		"\n".join(objs1 - objs2),
		"\n".join(objs2 - objs1),
		f"{len(objs1 & objs2)} objects"
	)
	
	console.print(table)
# ──────────────────────────────────────────────────────────────
# PHASE 1: ADVANCED SOURCE CODE SEARCH
# ──────────────────────────────────────────────────────────────

def search_source_with_context(connection, search_pattern, context_lines=4, owner=None, object_type=None):
	"""
	Search ALL_SOURCE with ±N lines of context around matches
	
	Args:
		connection: Oracle connection
		search_pattern: Text to search for
		context_lines: Number of context lines before/after (default: 4)
		owner: Optional schema filter (default: current user)
		object_type: Optional object type filter (PACKAGE, PROCEDURE, etc.)
	"""
	if owner is None:
		# Get current user if not specified
		with connection.cursor() as cursor:
			cursor.execute("SELECT USER FROM DUAL")
			owner = cursor.fetchone()[0]
	
	# Build WHERE clause
	where_parts = ["UPPER(s.TEXT) LIKE UPPER(:pattern)"]
	bind_vars = {'pattern': f'%{search_pattern}%'}
	
	if owner:
		where_parts.append("s.OWNER = :owner")
		bind_vars['owner'] = owner.upper()
	
	if object_type:
		where_parts.append("s.TYPE = :obj_type")
		bind_vars['obj_type'] = object_type.upper()
	
	where_clause = " AND ".join(where_parts)
	
	query = f"""
	WITH matches AS (
		SELECT DISTINCT s.OWNER, s.NAME, s.TYPE, s.LINE 
		FROM ALL_SOURCE s
		WHERE {where_clause}
	),
	context_lines AS (
		SELECT 
			src.OWNER,
			src.NAME,
			src.TYPE,
			src.LINE,
			src.TEXT,
			CASE 
				WHEN m.LINE IS NOT NULL THEN '>>> MATCH <<<'
				ELSE '...context...'
			END as CONTEXT
		FROM ALL_SOURCE src
		LEFT JOIN matches m 
			ON m.OWNER = src.OWNER 
			AND m.NAME = src.NAME 
			AND m.TYPE = src.TYPE 
			AND m.LINE = src.LINE
		WHERE EXISTS (
			SELECT 1 FROM matches m2
			WHERE m2.OWNER = src.OWNER 
			AND m2.NAME = src.NAME 
			AND m2.TYPE = src.TYPE
			AND ABS(src.LINE - m2.LINE) <= :ctx_lines
		)
	)
	SELECT 
		OWNER,
		NAME,
		TYPE,
		LINE,
		CONTEXT,
		TEXT
	FROM context_lines
	ORDER BY OWNER, NAME, TYPE, LINE
	"""
	
	bind_vars['ctx_lines'] = context_lines
	
	with connection.cursor() as cursor:
		cursor.execute(query, bind_vars)
		return cursor.fetchall()

def cmd_search_source(connection, args):
	"""
	Command handler for source code search
	Usage: search source <pattern> [options]
	Options:
	  -c, --context N    Number of context lines (default: 4)
	  -o, --owner OWNER  Schema owner to search
	  -t, --type TYPE    Object type filter
	  -h, --help         Show help
	"""
	if not args or args.strip() in ['--help', '-h']:
		console.print("[bold]Usage:[/bold] search source <pattern> [options]")
		console.print("[bold]Options:[/bold]")
		console.print("  -c, --context N    Number of context lines (default: 4)")
		console.print("  -o, --owner OWNER  Schema owner to search")
		console.print("  -t, --type TYPE    Object type filter")
		console.print("  -h, --help         Show this help")
		console.print("\n[bold]Examples:[/bold]")
		console.print("  search source 'ses_valida'")
		console.print("  search source 'ses_valida' -c 3 -t PACKAGE")
		console.print("  search source 'ses_valida' --owner OTHER_SCHEMA")
		return

	if not args:
		console.print("[red]Usage: search source <pattern> [options][/red]")
		console.print("Example: search source 'ses_valida' -c 3")
		return
	
	# Parse arguments
	import shlex
	try:
		parsed_args = shlex.split(args) if isinstance(args, str) else args
	except:
		parsed_args = args.split() if isinstance(args, str) else args
	
	if not parsed_args:
		console.print("[red]No search pattern provided[/red]")
		return
	
	# Simple parsing for now (can be enhanced with argparse later)
	pattern = parsed_args[0]
	context_lines = 4
	owner = None
	object_type = None
	
	i = 1
	while i < len(parsed_args):
		arg = parsed_args[i]
		if arg in ['-c', '--context'] and i + 1 < len(parsed_args):
			try:
				context_lines = int(parsed_args[i + 1])
				i += 2
			except ValueError:
				console.print(f"[red]Invalid context value: {parsed_args[i + 1]}[/red]")
				return
		elif arg in ['-o', '--owner'] and i + 1 < len(parsed_args):
			owner = parsed_args[i + 1]
			i += 2
		elif arg in ['-t', '--type'] and i + 1 < len(parsed_args):
			object_type = parsed_args[i + 1]
			i += 2
		elif arg in ['-h', '--help']:
			console.print(cmd_search_source.__doc__)
			return
		else:
			console.print(f"[red]Unknown option: {arg}[/red]")
			return
	
	# Execute search
	console.print(f"[bold]Searching for:[/bold] '{pattern}'")
	console.print(f"[dim]Context: ±{context_lines} lines[/dim]")
	if owner:
		console.print(f"[dim]Owner: {owner}[/dim]")
	if object_type:
		console.print(f"[dim]Type: {object_type}[/dim]")
	
	results = search_source_with_context(
		connection, pattern, context_lines, owner, object_type
	)
	
	if not results:
		console.print(f"[yellow]No matches found for '{pattern}'[/yellow]")
		return
	
	# Display results
	current_object = None
	match_count = 0
	object_count = 0
	
	for owner, name, obj_type, line, context, text in results:
		obj_name = f"{owner}.{name} ({obj_type})"
		if obj_name != current_object:
			console.print(f"\n[bold cyan]── {obj_name} ──[/bold cyan]")
			current_object = obj_name
			object_count += 1
		
		if context == '>>> MATCH <<<':
			style = "bold yellow"
			match_count += 1
		else:
			style = "dim"
		
		console.print(f"{line:6d} [{style}]{context:15}[/{style}] {text.rstrip() if text else ''}")
	
	console.print(f"\n[green]✓ Found {match_count} matches in {object_count} objects[/green]")

# ──────────────────────────────────────────────────────────────
# PHASE 2: OBJECT SEARCH AND STATISTICS
# ──────────────────────────────────────────────────────────────

def find_objects(connection, pattern):
	"""Search objects by pattern"""
	pattern = f"%{pattern.upper()}%"
	with connection.cursor() as cursor:
		cursor.execute("""
			SELECT object_name, object_type, created, last_ddl_time
			FROM user_objects 
			WHERE object_name LIKE :1 
			ORDER BY object_type, object_name
		""", [pattern])
		objects = cursor.fetchall()
	
	if not objects:
		console.print(f"[yellow]No objects found matching '{pattern}'[/yellow]")
		return
	
	table = Table(title=f"Objects matching: {pattern}")
	table.add_column("Name", style="cyan")
	table.add_column("Type", style="green")
	table.add_column("Created", style="dim")
	table.add_column("Last DDL", style="dim")
	
	for obj_name, obj_type, created, last_ddl in objects:
		table.add_row(obj_name, obj_type, created.strftime("%Y-%m-%d"), last_ddl.strftime("%Y-%m-%d"))
	
	console.print(table)

def show_object_stats(connection, obj_name):
	"""Show statistics for database object"""
	obj_name = obj_name.upper()
	with connection.cursor() as cursor:
		cursor.execute("""
			SELECT object_type, created, last_ddl_time, status, temporary
			FROM user_objects WHERE object_name = :1
		""", [obj_name])
		obj_info = cursor.fetchone()
		
		if not obj_info:
			console.print(f"[red]Object '{obj_name}' not found[/red]")
			return
		
		obj_type, created, last_ddl, status, temporary = obj_info
		
		table = Table(title=f"Statistics: {obj_name}")
		table.add_column("Property", style="cyan")
		table.add_column("Value", style="white")
		
		table.add_row("Type", obj_type)
		table.add_row("Status", status)
		table.add_row("Temporary", "YES" if temporary == "Y" else "NO")
		table.add_row("Created", created.strftime("%Y-%m-%d %H:%M"))
		table.add_row("Last DDL", last_ddl.strftime("%Y-%m-%d %H:%M"))
		
		if obj_type in ("TABLE", "VIEW"):
			cursor.execute("SELECT num_rows FROM user_tables WHERE table_name = :1", [obj_name])
			num_rows = cursor.fetchone()
			if num_rows:
				table.add_row("Rows", str(num_rows[0]))
		
		console.print(table)
# ──────────────────────────────────────────────────────────────
# PHASE 4: GLOBAL AUDIT TRACKER (NEW)
# ──────────────────────────────────────────────────────────────

def collect_schema_metadata(connection, owner=None):
	"""Collect comprehensive schema metadata"""
	if owner is None:
		with connection.cursor() as cursor:
			cursor.execute("SELECT USER FROM DUAL")
			owner = cursor.fetchone()[0]
	
	metadata = {
		'timestamp': datetime.datetime.now().isoformat(),
		'owner': owner.upper(),
		'tables': {},
		'views': {},
		'procedures': {},
		'functions': {},
		'packages': {},
		'triggers': {},
		'indexes': {},
		'constraints': {},
		'sequences': {}
	}
	
	with connection.cursor() as cursor:
		# Tables with columns
		cursor.execute("""
			SELECT table_name, column_name, data_type, data_length, 
				   data_precision, data_scale, nullable
			FROM all_tab_columns 
			WHERE owner = :1 
			ORDER BY table_name, column_id
		""", [owner])
		for table, column, dtype, dlen, prec, scale, nullable in cursor:
			if table not in metadata['tables']:
				metadata['tables'][table] = {'columns': [], 'constraints': []}
			col_def = f"{column} {dtype}"
			if dtype == "NUMBER" and prec:
				col_def += f"({prec},{scale or 0})"
			elif dlen:
				col_def += f"({dlen})"
			col_def += " NULL" if nullable == "Y" else " NOT NULL"
			metadata['tables'][table]['columns'].append(col_def)
		
		# Views
		cursor.execute("""
			SELECT view_name, text FROM all_views 
			WHERE owner = :1 ORDER BY view_name
		""", [owner])
		for view_name, text in cursor:
			metadata['views'][view_name] = text
		
		# Procedures & Functions
		cursor.execute("""
			SELECT object_name, object_type FROM all_objects 
			WHERE owner = :1 AND object_type IN ('PROCEDURE', 'FUNCTION', 'PACKAGE', 'TRIGGER')
			ORDER BY object_type, object_name
		""", [owner])
		for obj_name, obj_type in cursor:
			key = obj_type.lower() + 's'
			if key not in metadata:
				metadata[key] = {}
			metadata[key][obj_name] = {'source': ''}
		
		# Get source for code objects
		for obj_type in ['PROCEDURE', 'FUNCTION', 'PACKAGE', 'PACKAGE BODY', 'TRIGGER']:
			cursor.execute("""
				SELECT name, type, text FROM all_source 
				WHERE owner = :1 AND type = :2
				ORDER BY name, line
			""", [owner, obj_type])
			for name, typ, text in cursor:
				typ_key = typ.lower().replace(' ', '_') + 's'
				if typ_key not in metadata:
					metadata[typ_key] = {}
				if name not in metadata[typ_key]:
					metadata[typ_key][name] = {'source': ''}
				metadata[typ_key][name]['source'] += text or ''
	
	return metadata

def save_audit_snapshot(connection, schema_name, snapshot_name=None):
	"""Save schema snapshot to JSON file with validation"""
	import re
	
	# Validate schema name
	if not re.match(r'^[A-Za-z0-9_]+$', schema_name):
		raise ValueError(f"Invalid schema name: {schema_name}")
	
	if snapshot_name:
		# Prevent path traversal and ensure safe filename
		if not re.match(r'^[A-Za-z0-9_.-]+$', snapshot_name):
			raise ValueError(f"Invalid snapshot name: {snapshot_name}")
		if '..' in snapshot_name or '/' in snapshot_name or '\\' in snapshot_name:
			raise ValueError("Snapshot name cannot contain path traversal characters")
	
	schema_dir = audit_dir / schema_name
	schema_dir.mkdir(parents=True, exist_ok=True)
	
	if snapshot_name is None:
		timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
		snapshot_name = f"{schema_name}_{timestamp}"
	
	metadata = collect_schema_metadata(connection)
	snapshot_file = schema_dir / f"{snapshot_name}.json"
	
	# Prevent overwriting without confirmation
	if snapshot_file.exists():
		console.print(f"[yellow]Snapshot '{snapshot_name}' already exists[/yellow]")
		response = console.input("Overwrite? (y/N): ").lower()
		if response != 'y':
			console.print("[yellow]Snapshot cancelled[/yellow]")
			return snapshot_file
	
	with open(snapshot_file, 'w', encoding='utf-8') as f:
		json_lib.dump(metadata, f, indent=2, default=json_serial, ensure_ascii=False)
	
	return snapshot_file

def load_snapshot(schema_name, snapshot_name):
	"""Load snapshot from file"""
	snapshot_file = audit_dir / schema_name / f"{snapshot_name}.json"
	if not snapshot_file.exists():
		return None
	
	with open(snapshot_file, 'r', encoding='utf-8') as f:
		return json_lib.load(f)

def compare_snapshots(snap1, snap2):
	"""Compare two snapshots and return differences"""
	from difflib import unified_diff
	
	changes = {
		'added': {},
		'removed': {},
		'modified': {},
		'summary': {}
	}
	
	# Compare tables
	tables1 = set(snap1.get('tables', {}).keys())
	tables2 = set(snap2.get('tables', {}).keys())
	
	if tables2 - tables1:
		changes['added']['tables'] = list(tables2 - tables1)
	if tables1 - tables2:
		changes['removed']['tables'] = list(tables1 - tables2)
	
	# Check for modified tables (column changes)
	common_tables = tables1 & tables2
	for table in common_tables:
		cols1 = snap1['tables'][table].get('columns', [])
		cols2 = snap2['tables'][table].get('columns', [])
		if cols1 != cols2:
			if 'tables' not in changes['modified']:
				changes['modified']['tables'] = {}
			changes['modified']['tables'][table] = {
				'before': cols1,
				'after': cols2
			}
	
	# Compare other object types
	for obj_type in ['views', 'procedures', 'functions', 'packages', 'triggers']:
		objs1 = set(snap1.get(obj_type, {}).keys())
		objs2 = set(snap2.get(obj_type, {}).keys())
		
		added = list(objs2 - objs1)
		removed = list(objs1 - objs2)
		
		if added:
			changes['added'][obj_type] = added
		if removed:
			changes['removed'][obj_type] = removed
		
		# Check for modifications in code objects
		if obj_type in ['procedures', 'functions', 'packages', 'triggers']:
			common = objs1 & objs2
			for obj in common:
				source1 = snap1[obj_type][obj].get('source', '')
				source2 = snap2[obj_type][obj].get('source', '')
				if source1 != source2:
					if obj_type not in changes['modified']:
						changes['modified'][obj_type] = {}
					changes['modified'][obj_type][obj] = {
						'diff': list(unified_diff(
							source1.splitlines(),
							source2.splitlines(),
							lineterm='',
							fromfile='before',
							tofile='after'
						))
					}
	
	# Generate summary counts
	for change_type in ['added', 'removed', 'modified']:
		total = 0
		for obj_type, items in changes[change_type].items():
			if isinstance(items, dict):
				total += len(items)
			else:
				total += len(items)
		changes['summary'][change_type] = total
	
	return changes

def generate_audit_report(changes, schema_name, snap1_name, snap2_name):
	"""Generate audit report of changes"""
	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	
	report = f"""
    ╔══════════════════════════════════════════════════════════╗
    ║                SCHEMA AUDIT REPORT                       ║
    ╠══════════════════════════════════════════════════════════╣
    ║ Schema:     {schema_name:<40} ║
    ║ Compared:   {snap1_name} → {snap2_name:<30} ║
    ║ Generated:  {timestamp:<40} ║
    ║ Changes:    {changes['summary']['added']} added, {changes['summary']['removed']} removed, {changes['summary']['modified']} modified ║
    ╚══════════════════════════════════════════════════════════╝
    """
	
	# Detailed changes
	details = "\n📊 DETAILED CHANGES:\n"
	details += "═" * 60 + "\n"
	
	for change_type, title in [('added', '➕ ADDED'), ('removed', '➖ REMOVED'), ('modified', '✏️ MODIFIED')]:
		if changes['summary'][change_type] > 0:
			details += f"\n{title}:\n"
			details += "─" * 40 + "\n"
			
			for obj_type, items in changes[change_type].items():
				if items:
					if isinstance(items, dict):
						details += f"  {obj_type.upper()}:\n"
						for obj_name, diff in items.items():
							details += f"    • {obj_name}\n"
							if 'diff' in diff:
								for line in diff['diff'][:5]:  # Show first 5 diff lines
									if line.startswith('+'):
										details += f"      [green]{line}[/green]\n"
									elif line.startswith('-'):
										details += f"      [red]{line}[/red]\n"
									else:
										details += f"      {line}\n"
					else:
						details += f"  {obj_type.upper()}:\n"
						for item in items:
							details += f"    • {item}\n"
	
	return report + details
# ──────────────────────────────────────────────────────────────
# AUDIT COMMANDS
# ──────────────────────────────────────────────────────────────

def cmd_audit_snapshot(state, args):
	"""Command: audit snapshot <schema|ALL> [name]"""
	import shlex
	
	try:
		parts = shlex.split(args) if args else []
	except Exception as e:
		console.print(f"[red]Failed to parse arguments: {e}[/red]")
		return
	
	if len(parts) < 1:
		console.print("[red]Usage: audit snapshot <schema|ALL> [snapshot_name][/red]")
		return
	
	target = parts[0].upper()
	snapshot_name = parts[1] if len(parts) > 1 else None
	
	if target == "ALL":
		# Snapshot all monitored schemas
		schemas = state.audit_registry.registry.get("schemas", {}).keys()
		if not schemas:
			console.print("[yellow]No schemas in audit registry[/yellow]")
			return
		
		success_count = 0
		failed_schemas = []
		
		for schema in schemas:
			schema_info = state.audit_registry.registry["schemas"][schema]
			if not schema_info.get("enabled", False):
				console.print(f"[dim]Skipping disabled schema: {schema}[/dim]")
				continue
			
			conn_wrapper = state.audit_registry.get_schema_connection(schema)
			if conn_wrapper:
				try:
					with conn_wrapper as conn:
						snapshot_file = save_audit_snapshot(conn, schema, snapshot_name)
						state.audit_registry.update_schema_status(schema, snapshot_file.stem)
						console.print(f"[green]  ✓ {schema}: {snapshot_file.name}[/green]")
						success_count += 1
				except Exception as e:
					console.print(f"[red]  ✗ {schema}: {e}[/red]")
					failed_schemas.append(schema)
				finally:
					conn_wrapper.close()
			else:
				failed_schemas.append(schema)
		
		console.print(f"\n[bold]Global snapshot complete:[/bold]")
		console.print(f"  Successful: {success_count}/{len(schemas)} schemas")
		if failed_schemas:
			console.print(f"  Failed: {', '.join(failed_schemas)}")
		
	else:
		# Snapshot single schema
		if state.connection and target == state.current_profile.upper():
			# Use current connection
			snapshot_file = save_audit_snapshot(state.connection, target, snapshot_name)
			state.audit_registry.update_schema_status(target, snapshot_file.stem)
			console.print(f"[green]📸 Snapshot saved: {snapshot_file.name}[/green]")
			console.print(f"[dim]Location: {snapshot_file}[/dim]")
		else:
			# Get connection from registry
			conn_wrapper = state.audit_registry.get_schema_connection(target)
			if conn_wrapper:
				try:
					with conn_wrapper as conn:
						snapshot_file = save_audit_snapshot(conn, target, snapshot_name)
						state.audit_registry.update_schema_status(target, snapshot_file.stem)
						console.print(f"[green]📸 Snapshot saved: {snapshot_file.name}[/green]")
						console.print(f"[dim]Location: {snapshot_file}[/dim]")
				except Exception as e:
					console.print(f"[red]Failed to create snapshot: {e}[/red]")
				finally:
					conn_wrapper.close()

def cmd_audit_compare(state, args):
	"""Command: audit compare <schema> <snap1> <snap2>"""
	import shlex
	
	try:
		parts = shlex.split(args) if args else []
	except Exception as e:
		console.print(f"[red]Failed to parse arguments: {e}[/red]")
		return
	
	if len(parts) != 3:
		console.print("[red]Usage: audit compare <schema> <snapshot1> <snapshot2>[/red]")
		console.print("[dim]Example: audit compare HR 20240115_100000 20240115_110000[/dim]")
		return
	
	schema, snap1, snap2 = parts
	
	# Load snapshots
	snapshot1 = load_snapshot(schema, snap1)
	snapshot2 = load_snapshot(schema, snap2)
	
	if not snapshot1:
		console.print(f"[red]Snapshot '{snap1}' not found for schema '{schema}'[/red]")
		return
	if not snapshot2:
		console.print(f"[red]Snapshot '{snap2}' not found for schema '{schema}'[/red]")
		return
	
	# Compare
	changes = compare_snapshots(snapshot1, snapshot2)
	
	# Generate and display report
	report = generate_audit_report(changes, schema, snap1, snap2)
	console.print(report)
	
	# Save report to file
	report_file = audit_dir / schema / f"comparison_{snap1}_vs_{snap2}.txt"
	with open(report_file, 'w', encoding='utf-8') as f:
		f.write(report)
	
	console.print(f"[dim]Full report saved to: {report_file}[/dim]")

def cmd_audit_list(state, args):
	"""Command: audit list <schema>"""
	import shlex
	
	try:
		parts = shlex.split(args) if args else []
	except:
		parts = []
	
	if not parts:
		# List all schemas with snapshots
		schema_dirs = [d for d in audit_dir.iterdir() if d.is_dir()]
		
		if not schema_dirs:
			console.print("[yellow]No audit data found[/yellow]")
			return
		
		table = Table(title="Audit Overview - All Schemas")
		table.add_column("Schema", style="cyan")
		table.add_column("Snapshots", justify="right", style="green")
		table.add_column("Latest", style="dim")
		table.add_column("Size", style="dim")
		
		for schema_dir in schema_dirs:
			snapshots = list(schema_dir.glob("*.json"))
			if snapshots:
				latest = max(snapshots, key=lambda x: x.stat().st_mtime)
				latest_time = datetime.datetime.fromtimestamp(latest.stat().st_mtime)
				size_mb = sum(s.stat().st_size for s in snapshots) / (1024*1024)
				
				table.add_row(
					schema_dir.name,
					str(len(snapshots)),
					latest_time.strftime("%Y-%m-%d %H:%M"),
					f"{size_mb:.1f} MB"
				)
		
		console.print(table)
		return
	
	# List snapshots for specific schema
	schema = parts[0].strip()
	schema_dir = audit_dir / schema
	
	if not schema_dir.exists():
		console.print(f"[yellow]No audit data found for schema '{schema}'[/yellow]")
		return
	
	snapshots = list(schema_dir.glob("*.json"))
	snapshots.sort(key=lambda x: x.stat().st_mtime, reverse=True)
	
	if not snapshots:
		console.print(f"[yellow]No snapshots found for schema '{schema}'[/yellow]")
		return
	
	table = Table(title=f"Audit Snapshots: {schema}")
	table.add_column("Snapshot", style="cyan")
	table.add_column("Created", style="dim")
	table.add_column("Size", style="dim")
	table.add_column("Objects", style="green")
	
	for snapshot in snapshots[:20]:  # Show last 20
		with open(snapshot, 'r', encoding='utf-8') as f:
			data = json_lib.load(f)
			obj_count = (
				len(data.get('tables', {})) +
				len(data.get('views', {})) +
				len(data.get('procedures', {})) +
				len(data.get('functions', {})) +
				len(data.get('packages', {}))
			)
		
		created = datetime.datetime.fromtimestamp(snapshot.stat().st_mtime)
		size_kb = snapshot.stat().st_size / 1024
		
		table.add_row(
			snapshot.stem,
			created.strftime("%Y-%m-%d %H:%M"),
			f"{size_kb:.1f} KB",
			str(obj_count)
		)
	
	console.print(table)
	console.print(f"[dim]Showing {len(snapshots[:20])} of {len(snapshots)} snapshots[/dim]")

def cmd_audit_cleanup(state, args):
	"""Command: audit cleanup <schema> [keep_last]"""
	import shlex
	
	try:
		parts = shlex.split(args) if args else []
	except:
		parts = args.split() if args else []
	
	if len(parts) < 1:
		console.print("[red]Usage: audit cleanup <schema> [keep_last_N][/red]")
		console.print("[dim]Example: audit cleanup HR 10 (keeps last 10 snapshots)[/dim]")
		return
	
	schema = parts[0]
	keep_last = int(parts[1]) if len(parts) > 1 else 20
	
	schema_dir = audit_dir / schema
	if not schema_dir.exists():
		console.print(f"[yellow]No audit data found for schema '{schema}'[/yellow]")
		return
	
	snapshots = list(schema_dir.glob("*.json"))
	snapshots.sort(key=lambda x: x.stat().st_mtime)
	
	if len(snapshots) <= keep_last:
		console.print(f"[yellow]Only {len(snapshots)} snapshots exist, none removed[/yellow]")
		return
	
	to_remove = snapshots[:-keep_last]  # Keep last N
	removed_count = 0
	total_freed = 0
	
	for snapshot in to_remove:
		size = snapshot.stat().st_size
		try:
			snapshot.unlink()
			removed_count += 1
			total_freed += size
		except Exception as e:
			console.print(f"[red]Failed to remove {snapshot.name}: {e}[/red]")
	
	console.print(f"[green]🧹 Cleanup complete:[/green]")
	console.print(f"  Removed: {removed_count} snapshots")
	console.print(f"  Kept: {len(snapshots) - removed_count} snapshots")
	console.print(f"  Space freed: {total_freed / (1024*1024):.2f} MB")
# ──────────────────────────────────────────────────────────────
# AUDIT MONITOR AND EXPORT COMMANDS
# ──────────────────────────────────────────────────────────────

def cmd_audit_monitor(state, args):
	"""Command: audit monitor <add|remove|list|status|enable|disable> [args]"""
	import shlex
	
	try:
		parsed_args = shlex.split(args) if args else []
	except Exception as e:
		console.print(f"[red]Failed to parse arguments: {e}[/red]")
		console.print("[yellow]Hint: Use quotes for passwords with spaces[/yellow]")
		return
	
	if not parsed_args:
		console.print("[red]Usage: audit monitor <add|remove|list|status|enable|disable> [args][/red]")
		console.print("[dim]Examples:[/dim]")
		console.print("  audit monitor add HR hr_user 'my password' host:1521/service")
		console.print("  audit monitor remove HR")
		console.print("  audit monitor list")
		console.print("  audit monitor status")
		console.print("  audit monitor enable HR")
		console.print("  audit monitor disable HR")
		return
	
	action = parsed_args[0].lower()
	registry = state.audit_registry
	
	if action == "add" and len(parsed_args) >= 5:
		schema_name = parsed_args[1]
		user = parsed_args[2]
		password = parsed_args[3]
		dsn = parsed_args[4]
		enabled = True if len(parsed_args) < 6 else parsed_args[5].lower() not in ['0', 'false', 'no', 'disabled']
		
		registry.add_schema(schema_name, user, password, dsn, enabled)
		
	elif action == "remove" and len(parsed_args) >= 2:
		schema_name = parsed_args[1]
		registry.remove_schema(schema_name)
		
	elif action == "enable" and len(parsed_args) >= 2:
		schema_name = parsed_args[1]
		if schema_name in registry.registry.get("schemas", {}):
			registry.registry["schemas"][schema_name]["enabled"] = True
			registry._save_registry()
			console.print(f"[green]✓ Schema '{schema_name}' enabled[/green]")
		else:
			console.print(f"[red]Schema '{schema_name}' not found[/red]")
			
	elif action == "disable" and len(parsed_args) >= 2:
		schema_name = parsed_args[1]
		if schema_name in registry.registry.get("schemas", {}):
			registry.registry["schemas"][schema_name]["enabled"] = False
			registry._save_registry()
			console.print(f"[green]✓ Schema '{schema_name}' disabled[/green]")
		else:
			console.print(f"[red]Schema '{schema_name}' not found[/red]")
		
	elif action == "list":
		registry.list_schemas()
		
	elif action == "status":
		status = registry.get_global_status()
		console.print("\n[bold cyan]🔍 GLOBAL AUDIT STATUS[/bold cyan]")
		console.print("═" * 40)
		console.print(f"Enabled: {'✓' if status.get('audit_enabled') else '✗'}")
		console.print(f"Monitored schemas: {len(status.get('monitored_schemas', []))}")
		console.print(f"Total snapshots: {status.get('total_snapshots', 0)}")
		
		last_snapshot = status.get('last_global_snapshot')
		if last_snapshot:
			try:
				dt = datetime.datetime.fromisoformat(last_snapshot.replace('Z', '+00:00'))
				console.print(f"Last snapshot: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
			except:
				console.print(f"Last snapshot: {last_snapshot}")
		
		if status.get('monitored_schemas'):
			console.print("\n[bold]Monitored schemas:[/bold]")
			for schema in status['monitored_schemas']:
				schema_info = registry.registry["schemas"].get(schema, {})
				enabled = schema_info.get("enabled", False)
				status_icon = "🟢" if enabled else "🔴"
				snapshots = schema_info.get("snapshot_count", 0)
				console.print(f"  {status_icon} {schema} ({snapshots} snapshots)")
	else:
		console.print("[red]Invalid audit monitor command[/red]")

def cmd_export(state, args):
	"""Command: export <csv|json> <filename>"""
	import shlex
	
	if not state.last_result:
		console.print("[red]No query results to export[/red]")
		return
	
	try:
		parts = shlex.split(args) if args else []
	except:
		parts = args.split() if args else []
	
	if len(parts) != 2:
		console.print("[red]Usage: export <csv|json> <filename>[/red]")
		console.print("[dim]Examples:[/dim]")
		console.print("  export csv results.csv")
		console.print("  export json results.json")
		return
	
	fmt, filename = parts[0].lower(), parts[1]
	visible_headers = state.last_result.get_visible_headers()
	visible_indices = state.last_result.get_visible_indices()
	data = [[row[i] for i in visible_indices] for row in state.last_result.rows]
	
	try:
		if fmt == 'csv':
			with open(filename, 'w', newline='', encoding='utf-8') as f:
				writer = csv.writer(f)
				writer.writerow(visible_headers)
				writer.writerows([[c if c is not None else "" for c in row] for row in data])
			console.print(f"[green]Exported {len(data)} rows to CSV → {filename}[/green]")
			logging.info(f"Exported CSV: {filename} with {len(data)} rows")
		elif fmt == 'json':
			with open(filename, 'w', encoding='utf-8') as f:
				json_lib.dump([dict(zip(visible_headers, row)) for row in data],
					f, indent=2, default=json_serial, ensure_ascii=False)
			console.print(f"[green]Exported {len(data)} rows to JSON → {filename}[/green]")
			logging.info(f"Exported JSON: {filename} with {len(data)} rows")
		else:
			console.print("[red]Use: export csv file.csv or export json file.json[/red]")
	except Exception as e:
		console.print(f"[red]Export failed: {e}[/red]")
		logging.error(f"Export failed: {e}")

def cmd_history(args=None):
	"""List command history"""
	history_path = Path.home() / ".pyorasql_history"
	if not history_path.exists():
		console.print("[yellow]No history file found.[/yellow]")
		return
	
	try:
		with open(history_path, 'r', encoding='utf-8') as f:
			lines = f.readlines()
		
		# Prompt-toolkit history file usually has '+cmd' format or raw lines
		history = []
		for line in lines:
			clean = line.strip()
			if clean.startswith('+'): clean = clean[1:]
			if clean and (not history or history[-1] != clean):
				history.append(clean)
		
		filter_str = args.upper() if args else None
		
		table = Table(title="Command History", box=box.SIMPLE)
		table.add_column("#", justify="right", style="dim")
		table.add_column("Command")
		
		count = 0
		start_idx = max(0, len(history) - 50)
		for i, cmd in enumerate(history[start_idx:], start_idx + 1):
			if not filter_str or filter_str in cmd.upper():
				table.add_row(str(i), cmd)
				count += 1
		
		console.print(table)
		if filter_str:
			console.print(f"[dim]Found {count} matching commands.[/dim]")
	except Exception as e:
		console.print(f"[red]Error reading history: {e}[/red]")

# ──────────────────────────────────────────────────────────────
# HELP MENU
# ──────────────────────────────────────────────────────────────

def print_legend():
	"""Ultra-compact yet complete help menu with examples"""
	# Header
	console.print("\n[bold cyan]pyOraSQL v2.0 - All Commands[/bold cyan]")
	console.print("[dim]Type commands without ; SQL requires ;[/dim]\n")
	
	# Compact command grid - all commands in minimal space
	commands_grid = [
		# Connection
		("[bold magenta]Connection[/]", "connect <profile>", "profiles"),
		# Schema
		("[bold magenta]Schema[/]", "tables", "desc <obj>", "src <obj>", "view <obj>"),
		# Search
		("[bold magenta]Search[/]", "find <pat>", "search source <pat>", "  stats <obj>"),
		# Dependencies
		("[bold magenta]Deps[/]", "deps <obj>", "deps graph <obj>", "deps tree <obj>"),
		# Compare
		("[bold magenta]Compare[/]", "schema snapshot <name>", "schema diff <s1> <s2>"),
		# Audit (NEW)
		("[bold magenta]Audit[/]", "audit snapshot <s|ALL>", "audit compare <s> <s1> <s2>", "audit list [s]", "audit monitor <cmd>"),
		# Cache (NEW)
		("[bold magenta]Cache[/]", "cache clear", "cache ttl=<seconds>", "cache invalidate <type>"),
		# Results
		("[bold magenta]Results[/]", "show", "columns", "hide <cols>", "keep <cols>", "unhide"),
		# Output & Export
		("[bold magenta]Export[/]", "set output fmt", "export csv <file>", "export json <file>"),
		# General
		("[bold magenta]General[/]", "help", "history", "clear", "exit/quit/q"),
	]
	
	# Print all commands in a tight grid
	for category, *cmds in commands_grid:
		console.print(category)
		line = "  "
		for cmd in cmds:
			if len(line) + len(cmd) + 3 > console.width:
				console.print(line)
				line = "  "
			line += f"[cyan]{cmd:<18}[/cyan]"
		console.print(line)
	
	# Quick examples in one line - UPDATED WITH MORE EXAMPLES
	console.print("\n[bold yellow]Examples:[/bold yellow]")

	examples = [
		("connect dev", "Switch to dev database"),
		("tables", "List all tables"),
		("desc EMPLOYEES", "Show table structure"),
		("find %PROC%", "Find procedures"),
		("search source 'pattern'", "Search source code"),
		("deps graph MY_PACK", "Show dependencies"),
		("audit snapshot HR", "Save schema snapshot"),
		("audit monitor add HR user pass host:1521/service", "Add schema to audit"),
		("SELECT * FROM DUAL;", "Execute SQL"),
		("set output json", "JSON output"),
		("export csv results.csv", "Export to CSV"),
		("cache ttl=60", "Set cache TTL to 60s"),
		("cache clear", "Clear all caches"),
	]
	
	# Show examples in compact format
	example_line = ""
	for cmd, desc in examples:
		ex = f"[cyan]{cmd}[/cyan] [dim]({desc})[/dim]"
		if len(example_line) + len(ex) + 3 > console.width:
			console.print(f"  {example_line}")
			example_line = ex + " | "
		else:
			example_line += ex + " | "
	
	if example_line:
		console.print(f"  {example_line.rstrip(' | ')}")
	
	# Status and tips in minimal space
	console.print("\n[bold yellow]Status:[/bold yellow]")
	console.print("  [dev]C🟢A🟢> = Connected, Cached, AutoComplete ON")
	console.print("  [none]C🔴A🔴> = Not connected")
	
	# Audit status
	global_status_file = Path("audit/global_status.json")
	if global_status_file.exists():
		try:
			with open(global_status_file, 'r') as f:
				status = json_lib.load(f)
				monitored = len(status.get('monitored_schemas', []))
				if monitored > 0:
					console.print(f"  [audit] Monitoring {monitored} schema(s)")
		except:
			pass
	
	console.print("\n[bold yellow]Tips:[/bold yellow]")
	console.print("  [dim]• Tab=complete • ↑↓=history • ;=SQL end • hide/keep=columns[/dim]")
	console.print("  [dim]• Output: table/vertical/json/csv • Export: csv/json[/dim]")
	console.print("  [dim]• Cache: clear, ttl, invalidate • Passwords: use quotes for spaces[/dim]")

# ──────────────────────────────────────────────────────────────
# MAIN FUNCTION
# ──────────────────────────────────────────────────────────────
def main():
	connections = load_connections()
	state = ApplicationState()

	console.print("[bold green]pyOraSQL v2.0 — Complete Oracle Client[/bold green]")
	console.print(f"[dim]Client Mode: {CLIENT_MODE.upper()} | Cache: 🟢 | Autocomplete: 🟢[/dim]")
	print_legend()

	session = PromptSession(
		history=FileHistory(Path.home() / ".pyorasql_history"),
		lexer=PygmentsLexer(SqlLexer),
		complete_while_typing=True
	)

	try:
		while True:
			# Build prompt
			profile_display = state.current_profile or "none"
			cache_status = "🟢" if state.cache else "🔴"
			complete_status = "🟢" if state.completer else "🔴"
			
			prompt_html = HTML(
				f"<b><magenta>[{profile_display}]</magenta></b> "
				f"<ansigreen>C{cache_status}</ansigreen>"
				f"<ansicyan>A{complete_status}</ansicyan>"
				f"<b>&gt;</b> "
			)
			
			current_completer = state.completer if state.completer else None
			line = session.prompt(prompt_html, completer=current_completer).strip()
			
			if not line:
				continue

			if not line.endswith(';'):
				parts = line.split()
				if not parts:
					continue
				cmd = parts[0].lower()

				if cmd == 'connect':
					if len(parts) == 1:
						console.print(f"Current: [bold]{state.current_profile or 'none'}[/bold]")
						console.print(f"Available: {', '.join(connections.keys()) or 'none'}")
					else:
						state = switch_connection(parts[1], connections, state)

				elif cmd == 'profiles':
					for name, cfg in connections.items():
						mark = " ← current" if name == state.current_profile else ""
						console.print(f"  [cyan]{name}[/cyan] → {cfg['user']}@{cfg['dsn']}{mark}")

				elif state.connection:
					if cmd == 'tables':
						cmd_tables(state.connection)
					elif cmd in {'desc', 'describe'} and len(parts) == 2:
						cmd_describe(state.connection, parts[1])
					elif cmd == 'src' and len(parts) == 2:
						cmd_src(state.connection, parts[1])
					elif cmd == 'view' and len(parts) == 2:
						cmd_view(state.connection, parts[1])
					elif cmd == 'deps' and len(parts) == 2:
						interactive_deps_explorer(state.connection, parts[1])
					elif cmd == 'deps' and len(parts) == 3 and parts[1] == 'graph':
						draw_dependency_graph(state.connection, parts[2])
					elif cmd == 'deps' and len(parts) == 3 and parts[1] == 'tree':
						draw_dependency_tree(state.connection, parts[2])
					elif cmd == 'schema' and len(parts) == 3 and parts[1] == 'snapshot':
						state = take_schema_snapshot(state.connection, parts[2], state)
					elif cmd == 'schema' and len(parts) == 4 and parts[1] == 'diff':
						compare_schemas(state, parts[2], parts[3])
					elif cmd == 'find' and len(parts) == 2:
						find_objects(state.connection, parts[1])
					elif cmd == 'stats' and len(parts) == 2:
						show_object_stats(state.connection, parts[1])
					elif cmd == 'search' and len(parts) >= 3 and parts[1] == 'source':
						search_args = " ".join(parts[2:])
						cmd_search_source(state.connection, search_args)

				# Global commands
				if cmd in {'exit', 'quit', 'q'}:
					break
				elif cmd == 'help':
					print_legend()
				elif cmd == 'clear':
					os.system('cls' if os.name == 'nt' else 'clear')
				elif cmd == 'history':
					hist_args = " ".join(parts[1:]) if len(parts) > 1 else None
					cmd_history(hist_args)
				elif cmd == 'set' and len(parts) >= 2 and parts[1].lower() == 'output':
					state.formatter.set_format(" ".join(parts[2:]) if len(parts) > 2 else "")
				elif cmd == 'show' and state.last_result:
					state.formatter.display(state.last_result)
				elif cmd == 'columns' and state.last_result:
					state.last_result.show_columns()
				elif cmd == 'hide' and len(parts) > 1 and state.last_result:
					to_hide = {p.upper() for p in parts[1:]}
					invalid = to_hide - set(state.last_result.original_headers)
					if invalid:
						console.print(f"[red]Unknown column(s): {', '.join(invalid)}[/red]")
					else:
						state.last_result.hidden_columns.update(to_hide)
						state.formatter.display(state.last_result)
				elif cmd == 'keep' and len(parts) > 1 and state.last_result:
					keep_set = {p.upper() for p in parts[1:]}
					invalid = keep_set - set(state.last_result.original_headers)
					if invalid:
						console.print(f"[red]Unknown column(s): {', '.join(invalid)}[/red]")
					else:
						state.last_result.hidden_columns = set(state.last_result.original_headers) - keep_set
						state.formatter.display(state.last_result)
				elif cmd == 'unhide' and state.last_result:
					if state.last_result.hidden_columns:
						count = len(state.last_result.hidden_columns)
						state.last_result.hidden_columns.clear()
						state.formatter.display(state.last_result)
						console.print(f"[green]{count} column(s) restored.[/green]")
				elif cmd == 'export' and len(parts) >= 2:
					export_args = " ".join(parts[1:])
					cmd_export(state, export_args)
				elif cmd == 'cache':
					if len(parts) == 2:
						if parts[1] == 'clear':
							if state.cache:
								state.cache.invalidate_cache()
							else:
								console.print("[yellow]No cache available[/yellow]")
						elif parts[1].startswith('ttl='):
							try:
								ttl = int(parts[1].split('=')[1])
								if state.cache:
									state.cache.set_cache_ttl(ttl)
								else:
									console.print("[yellow]No cache available[/yellow]")
							except ValueError:
								console.print("[red]Invalid TTL value[/red]")
						elif parts[1] == 'invalidate':
							if state.cache:
								state.cache.invalidate_cache('all')
							else:
								console.print("[yellow]No cache available[/yellow]")
						elif parts[1] in ['tables', 'objects', 'columns']:
							if state.cache:
								state.cache.invalidate_cache(parts[1])
							else:
								console.print("[yellow]No cache available[/yellow]")
						else:
							console.print("[red]Cache commands: clear, ttl=<seconds>, invalidate <type>[/red]")
					else:
						console.print("[red]Cache commands: clear, ttl=<seconds>, invalidate <type>[/red]")
				elif cmd == 'audit':
					if len(parts) >= 2:
						if parts[1] == 'snapshot' and len(parts) >= 3:
							audit_args = " ".join(parts[2:])
							cmd_audit_snapshot(state, audit_args)
						elif parts[1] == 'compare' and len(parts) >= 5:
							audit_args = " ".join(parts[2:])
							cmd_audit_compare(state, audit_args)
						elif parts[1] == 'list':
							audit_args = " ".join(parts[2:]) if len(parts) > 2 else ""
							cmd_audit_list(state, audit_args)
						elif parts[1] == 'cleanup' and len(parts) >= 3:
							audit_args = " ".join(parts[2:])
							cmd_audit_cleanup(state, audit_args)
						elif parts[1] == 'monitor' and len(parts) >= 2:
							audit_args = " ".join(parts[2:])
							cmd_audit_monitor(state, audit_args)
						else:
							console.print("[red]Available audit commands:[/red]")
							console.print("  audit snapshot <schema|ALL> [name]")
							console.print("  audit compare <schema> <snap1> <snap2>")
							console.print("  audit list [schema]")
							console.print("  audit cleanup <schema> [keep_last]")
							console.print("  audit monitor <add|remove|list|status|enable|disable>")
				continue

			# Handle SQL queries
			if state.connection:
				sql = line[:-1].strip()
				if sql:
					state.last_result = execute_sql(state.connection, sql, state.formatter)

	except KeyboardInterrupt:
		console.print("\n[dim]Use 'exit' to quit[/dim]")
	except EOFError:
		console.print("\n[yellow]👋 Goodbye![/yellow]")
	finally:
		if state.connection:
			state.connection.close()
	console.print("\n[bold blue]pyOraSQL session ended[/bold blue]")

if __name__ == "__main__":
	main()
