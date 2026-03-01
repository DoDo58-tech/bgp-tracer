import json
import os
import sqlite3
import threading
import hashlib
from functools import lru_cache
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Tuple, Any

# SQLite-based cache system: fake-connection frequency keyed by
# (fake_connection, YYYY-MM-DD) to avoid re-validating the same pair within the
# same day across multiple AS runs/processes.
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = PROJECT_ROOT / "cache"
SQLITE_CACHE_DB = CACHE_DIR / "fake_conn_cache.db"

# Thread-local storage for database connections
local = threading.local()

# Memory LRU cache for hot data (most frequently accessed)
@lru_cache(maxsize=10000)  # Cache up to 10,000 entries
def memory_lru_cache_key(fake_connection, date_str):
    return f"{fake_connection}|{date_str}"

# Legacy JSON cache variables (for backward compatibility)
FAKE_CONN_CACHE_DIR = CACHE_DIR
FAKE_CONN_CACHE_FILE = CACHE_DIR / "fake_conn_freq_cache.json"
FAKE_CONN_FREQ_CACHE: Dict[Tuple[str, str], Dict[str, Any]] = {}
FAKE_CONN_CACHE_LOADED = False


def get_db_connection():
    if not hasattr(local, 'connection'):
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        local.connection = sqlite3.connect(str(SQLITE_CACHE_DB), check_same_thread=False)
        local.connection.execute("PRAGMA journal_mode=WAL")  # Better concurrency
        local.connection.execute("PRAGMA synchronous=NORMAL")  # Balance performance/safety
        local.connection.execute("PRAGMA cache_size=-64000")  # 64MB cache
        init_database(local.connection)
    return local.connection

def init_database(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fake_connection_cache (
            fake_connection TEXT NOT NULL,
            date_str TEXT NOT NULL,
            frequency_data TEXT NOT NULL,  -- JSON data
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (fake_connection, date_str)
        )
    """)

    # 新增AS对缓存表 - 按AS对缓存而不是整个AS路径
    conn.execute("""
        CREATE TABLE IF NOT EXISTS as_pair_cache (
            as1 TEXT NOT NULL,
            as2 TEXT NOT NULL,
            date_str TEXT NOT NULL,
            is_fake INTEGER NOT NULL,  -- 0=合法连接, 1=假连接
            asrel_hash TEXT NOT NULL,
            timestamp TEXT,  -- BGP更新时间戳
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (as1, as2, date_str, asrel_hash)
        )
    """)

    # 为性能创建索引
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_as_pair_date ON as_pair_cache(date_str)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_as_pair_asrel ON as_pair_cache(asrel_hash)
    """)

    # Create indexes for performance
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_fake_conn_date ON fake_connection_cache(date_str)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_fake_conn_updated ON fake_connection_cache(updated_at)
    """)

    conn.commit()

def cleanup_old_cache_entries(days_to_keep=30):
    """Remove cache entries older than specified days."""
    try:
        conn = get_db_connection()
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)

        cursor = conn.execute("""
            DELETE FROM fake_connection_cache
            WHERE updated_at < ?
        """, (cutoff_date.isoformat(),))

        deleted_count = cursor.rowcount
        conn.commit()

        if deleted_count > 0:
            print(f"Cleaned up {deleted_count} old cache entries")

    except Exception as e:
        print(f"Failed to cleanup old cache entries: {e}")

def load_fake_conn_cache():
    """Load fake connection cache from disk once per process (legacy compatibility)."""
    global FAKE_CONN_FREQ_CACHE, FAKE_CONN_CACHE_LOADED
    if _FAKE_CONN_CACHE_LOADED:
        return

    try:
        # First try to migrate from JSON to SQLite if JSON exists
        if FAKE_CONN_CACHE_FILE.exists() and not SQLITE_CACHE_DB.exists():
            print("Migrating JSON cache to SQLite...")
            migrate_json_to_sqlite()

        # Load into memory cache for fast access
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT fake_connection, date_str, frequency_data
            FROM fake_connection_cache
        """)

        cache = {}
        for fake_conn, date_str, freq_data in cursor.fetchall():
            try:
                cache[(fake_conn, date_str)] = json.loads(freq_data)
            except json.JSONDecodeError:
                continue  # Skip corrupted entries

            FAKE_CONN_FREQ_CACHE = cache
        print(f"Loaded {len(cache)} cached fake connection validations from SQLite")

    except Exception as e:
        print(f"Failed to load fake connection cache: {e}")
        FAKE_CONN_FREQ_CACHE = {}
    finally:
        FAKE_CONN_CACHE_LOADED = True

def migrate_json_to_sqlite():
    """Migrate existing JSON cache to SQLite database."""
    try:
        if not FAKE_CONN_CACHE_FILE.exists():
            return

        print("Starting JSON to SQLite migration...")

        with open(FAKE_CONN_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        conn = get_db_connection()
        migrated_count = 0

        for k, v in data.items():
            if "|" in k:
                fake_conn, day_str = k.split("|", 1)
                try:
                    conn.execute("""
                        INSERT OR REPLACE INTO fake_connection_cache
                        (fake_connection, date_str, frequency_data, updated_at)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    """, (fake_conn, day_str, json.dumps(v)))
                    migrated_count += 1
                except Exception as e:
                    print(f"Failed to migrate entry {k}: {e}")

        conn.commit()
        print(f"Successfully migrated {migrated_count} cache entries to SQLite")

        # Backup and remove old JSON file
        backup_file = FAKE_CONN_CACHE_FILE.with_suffix('.json.backup')
        FAKE_CONN_CACHE_FILE.rename(backup_file)
        print(f"Old JSON cache backed up to {backup_file}")

    except Exception as e:
        print(f"Failed to migrate JSON cache to SQLite: {e}")


def save_fake_conn_cache():
    """Save fake connection cache to SQLite (legacy compatibility)."""
    global FAKE_CONN_FREQ_CACHE

    try:
        if not FAKE_CONN_FREQ_CACHE:
            return

        conn = get_db_connection()

        # Batch insert/update memory cache to database
        data_to_save = []
        for (fake_conn, day_str), freq_data in FAKE_CONN_FREQ_CACHE.items():
            data_to_save.append((fake_conn, day_str, json.dumps(freq_data)))

        conn.executemany("""
            INSERT OR REPLACE INTO fake_connection_cache
            (fake_connection, date_str, frequency_data, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, data_to_save)

        conn.commit()
        print(f"Saved {len(FAKE_CONN_FREQ_CACHE)} fake connection validations to SQLite cache")

    except Exception as e:
        print(f"Failed to save fake connection cache to SQLite: {e}")


def get_cached_fake_conn_frequency(fake_connection, day_str):
    """Get cached fake connection frequency with LRU memory cache + SQLite fallback."""
    # First check memory LRU cache
    cache_key = memory_lru_cache_key(fake_connection, day_str)
    if memory_lru_cache_key.cache_info().currsize > 0:
        # Check if we have this in LRU cache by trying to get it
        try:
            # This is a bit of a hack, but LRU cache doesn't have a "contains" method
            # We'll let it raise KeyError if not found
            cached_data = _get_from_memory_cache(cache_key)
            return cached_data
        except KeyError:
            pass  # Not in memory cache, continue to database

    # Not in memory cache, check SQLite database
    try:
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT frequency_data FROM fake_connection_cache
            WHERE fake_connection = ? AND date_str = ?
        """, (fake_connection, day_str))

        row = cursor.fetchone()
        if row:
            data = json.loads(row[0])
            # Store in memory LRU cache for future fast access
            put_in_memory_cache(cache_key, data)
            return data
        return {}
    except Exception as e:
        print(f"Failed to get cached fake connection frequency: {e}")
        return {}

def get_from_memory_cache(key: str) -> Dict[str, Any]:
    """Get data from memory LRU cache (helper function to work around lru_cache limitations)."""
    # This is a workaround since lru_cache decorated functions don't have direct access
    # We'll use a global dict to store the actual data
    if not hasattr(get_from_memory_cache, '_cache'):
        get_from_memory_cache._cache = {}
    return get_from_memory_cache._cache[key]

def put_in_memory_cache(key: str, data: Dict[str, Any]) -> None:
    """Put data in memory LRU cache."""
    if not hasattr(put_in_memory_cache, '_cache'):
        put_in_memory_cache._cache = {}

    # Simple LRU: keep only most recent 1000 entries
    if len(put_in_memory_cache._cache) >= 1000:
        # Remove oldest entries (simple implementation)
        oldest_keys = list(put_in_memory_cache._cache.keys())[:200]  # Remove 20%
        for old_key in oldest_keys:
            del put_in_memory_cache._cache[old_key]

    put_in_memory_cache._cache[key] = data


def set_cached_fake_conn_frequency(fake_connection, day_str, frequency_data):
    """Set cached fake connection frequency in both memory LRU cache and SQLite."""
    try:
        # Update SQLite database
        conn = get_db_connection()
        conn.execute("""
            INSERT OR REPLACE INTO fake_connection_cache
            (fake_connection, date_str, frequency_data, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (fake_connection, day_str, json.dumps(frequency_data)))
        conn.commit()

        # Update memory LRU cache for fast access
        cache_key = memory_lru_cache_key(fake_connection, day_str)
        put_in_memory_cache(cache_key, frequency_data)

        # Also update legacy memory cache for backward compatibility
        FAKE_CONN_FREQ_CACHE[(fake_connection, day_str)] = frequency_data

    except Exception as e:
        print(f"Failed to set cached fake connection frequency: {e}")


def is_fake_conn_cached(fake_connection, day_str):
    """Check if fake connection is cached in SQLite."""
    try:
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT 1 FROM fake_connection_cache
            WHERE fake_connection = ? AND date_str = ?
            LIMIT 1
        """, (fake_connection, day_str))
        return cursor.fetchone() is not None
    except Exception as e:
        print(f"Failed to check if fake connection is cached: {e}")
        return False


def clear_fake_conn_cache():
    """Clear SQLite, memory LRU cache, and legacy memory cache."""
    global FAKE_CONN_FREQ_CACHE, FAKE_CONN_CACHE_LOADED

    try:
        # Clear SQLite database
        conn = get_db_connection()
        conn.execute("DELETE FROM fake_connection_cache")
        conn.commit()
        print("SQLite cache cleared")

        # Clear memory LRU cache
        if hasattr(put_in_memory_cache, '_cache'):
            put_in_memory_cache._cache.clear()
            print("Memory LRU cache cleared")

        # Clear legacy memory cache
        FAKE_CONN_FREQ_CACHE.clear()
        FAKE_CONN_CACHE_LOADED = False

        # Remove legacy JSON file if it exists
        if FAKE_CONN_CACHE_FILE.exists():
            try:
                FAKE_CONN_CACHE_FILE.unlink()
                print("Legacy JSON cache file deleted")
            except Exception as e:
                print(f"Failed to delete legacy cache file: {e}")

    except Exception as e:
        print(f"Failed to clear fake connection cache: {e}")


def get_cache_stats():
    """Get comprehensive cache statistics including LRU cache."""
    try:
        # SQLite stats
        conn = get_db_connection()
        cursor = conn.execute("SELECT COUNT(*) FROM fake_connection_cache")
        sqlite_count = cursor.fetchone()[0]

        # Get database file size
        db_size_mb = SQLITE_CACHE_DB.stat().st_size / (1024 * 1024) if SQLITE_CACHE_DB.exists() else 0

        # Memory LRU cache stats
        lru_count = 0
        if hasattr(put_in_memory_cache, '_cache'):
            lru_count = len(put_in_memory_cache._cache)

        # Legacy memory cache stats
        memory_count = len(FAKE_CONN_FREQ_CACHE)

        # Legacy JSON stats
        json_exists = FAKE_CONN_CACHE_FILE.exists()
        json_size_mb = FAKE_CONN_CACHE_FILE.stat().st_size / (1024 * 1024) if json_exists else 0

        # Calculate memory usage estimates
        lru_memory_mb = lru_count * 0.001  # Rough estimate: 1KB per entry
        legacy_memory_mb = memory_count * 0.001

        return {
            "sqlite_entries": sqlite_count,
            "sqlite_db_size_mb": round(db_size_mb, 2),
            "lru_cache_entries": lru_count,
            "lru_cache_memory_mb": round(lru_memory_mb, 2),
            "legacy_memory_entries": memory_count,
            "legacy_memory_mb": round(legacy_memory_mb, 2),
            "legacy_json_exists": json_exists,
            "legacy_json_size_mb": round(json_size_mb, 2),
            "total_entries": sqlite_count,
            "cache_hit_efficiency": f"{lru_count}/{sqlite_count}" if sqlite_count > 0 else "N/A"
        }

    except Exception as e:
        print(f"Failed to get cache stats: {e}")
    return {
            "sqlite_entries": 0,
            "sqlite_db_size_mb": 0,
            "lru_cache_entries": 0,
            "lru_cache_memory_mb": 0,
            "legacy_memory_entries": 0,
            "legacy_memory_mb": 0,
            "legacy_json_exists": False,
            "legacy_json_size_mb": 0,
            "total_entries": 0,
            "error": str(e)
    }


# Cache for fake connection detection (as_path -> fake_connections mapping)
@lru_cache(maxsize=5000)  # Memory cache for frequently accessed paths
def memory_fake_conn_detection_key(as_path, asrel_hash):
    return f"{as_path}|{asrel_hash}"


def get_asrel_hash(as_relationships):
    """Calculate hash of AS relationship data for cache invalidation"""
    try:
        # Convert to sorted, deterministic string representation
        providers = as_relationships.get('providers', {})
        peers = as_relationships.get('peers', {})

        # Sort keys for deterministic hashing
        providers_str = json.dumps(sorted(providers.items()), sort_keys=True)
        peers_str = json.dumps(sorted(peers.items()), sort_keys=True)

        combined = f"{providers_str}|{peers_str}"
        return hashlib.md5(combined.encode()).hexdigest()
    except Exception as e:
        print(f"Error calculating AS relationship hash: {e}")
        return "error_hash"


def get_cached_fake_connection_detection(as_path, asrel_hash):
    """Get cached fake connection detection result"""
    try:
        # Check memory cache first
        mem_key = memory_fake_conn_detection_key(as_path, asrel_hash)
        try:
            mem_result = get_from_memory_cache(mem_key)
            if mem_result is not None:
                return mem_result
        except KeyError:
            pass  # Not in memory cache

        # Check SQLite cache
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT fake_connections FROM fake_connection_detection_cache
            WHERE as_path = ? AND asrel_hash = ?
        """, (as_path, asrel_hash))

        row = cursor.fetchone()
        if row:
            result = json.loads(row[0])
            # Store in memory cache for faster future access
            put_in_memory_cache(mem_key, result)
            return result

        return None
    except Exception as e:
        print(f"Error getting cached fake connection detection: {e}")
        return None


def set_cached_fake_connection_detection(as_path, asrel_hash, fake_connections):
    """Cache fake connection detection result"""
    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT OR REPLACE INTO fake_connection_detection_cache
            (as_path, asrel_hash, fake_connections)
            VALUES (?, ?, ?)
        """, (as_path, asrel_hash, json.dumps(fake_connections)))

        # Also store in memory cache
        mem_key = memory_fake_conn_detection_key(as_path, asrel_hash)
        put_in_memory_cache(mem_key, fake_connections)

        conn.commit()
    except Exception as e:
        print(f"Error caching fake connection detection: {e}")


def is_fake_connection_detection_cached(as_path, asrel_hash):
    """Check if fake connection detection result is cached"""
    try:
        # Check memory cache first
        mem_key = memory_fake_conn_detection_key(as_path, asrel_hash)
        try:
            get_from_memory_cache(mem_key)
            return True
        except KeyError:
            pass

        # Check SQLite cache
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT 1 FROM fake_connection_detection_cache
            WHERE as_path = ? AND asrel_hash = ?
            LIMIT 1
        """, (as_path, asrel_hash))

        return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error checking fake connection detection cache: {e}")
        return False


# ============== 新增AS对缓存函数 ==============

def get_cached_as_pair(as1, as2, date_str, asrel_hash):
    """Get cached AS pair connection status"""
    try:
        # Check memory cache first
        mem_key = f"as_pair:{as1}:{as2}:{date_str}:{asrel_hash}"
        try:
            return get_from_memory_cache(mem_key)
        except KeyError:
            pass

        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT is_fake, timestamp FROM as_pair_cache
            WHERE as1 = ? AND as2 = ? AND date_str = ? AND asrel_hash = ?
        """, (as1, as2, date_str, asrel_hash))

        row = cursor.fetchone()
        if row:
            result = {'is_fake': bool(row[0]), 'timestamp': row[1]}
            # Store in memory cache
            put_in_memory_cache(mem_key, result)
            return result

        return None
    except Exception as e:
        print(f"Error getting cached AS pair: {e}")
        return None


def set_cached_as_pair(as1, as2, date_str, asrel_hash, is_fake, timestamp=None):
    """Cache AS pair connection status

    Args:
        as1, as2: AS numbers
        date_str: Date string (YYYY-MM-DD format)
        asrel_hash: AS relationship hash
        is_fake: Boolean indicating if connection is fake
        timestamp: Date string (YYYY-MM-DD), defaults to date_str if None
    """
    try:
        # 确保时间戳是日期格式，如果没有提供则使用date_str
        if timestamp is None:
            timestamp = date_str
        else:
            # 如果提供了完整时间戳，只保留日期部分
            if ' ' in str(timestamp):
                timestamp = str(timestamp).split(' ')[0]

        conn = get_db_connection()
        conn.execute("""
            INSERT OR REPLACE INTO as_pair_cache
            (as1, as2, date_str, asrel_hash, is_fake, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (as1, as2, date_str, asrel_hash, 1 if is_fake else 0, timestamp))

        conn.commit()

        # Update memory cache
        mem_key = f"as_pair:{as1}:{as2}:{date_str}:{asrel_hash}"
        result = {'is_fake': is_fake, 'timestamp': timestamp}
        put_in_memory_cache(mem_key, result)

    except Exception as e:
        print(f"Error setting cached AS pair: {e}")


def is_as_pair_cached(as1, as2, date_str, asrel_hash):
    """Check if AS pair is cached"""
    try:
        # Check memory cache first
        mem_key = f"as_pair:{as1}:{as2}:{date_str}:{asrel_hash}"
        try:
            get_from_memory_cache(mem_key)
            return True
        except KeyError:
            pass

        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT 1 FROM as_pair_cache
            WHERE as1 = ? AND as2 = ? AND date_str = ? AND asrel_hash = ?
            LIMIT 1
        """, (as1, as2, date_str, asrel_hash))

        return cursor.fetchone() is not None
    except Exception as e:
        print(f"Error checking AS pair cache: {e}")
        return False
