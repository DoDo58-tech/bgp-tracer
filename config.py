"""Runtime configuration: env-driven secrets/paths plus compile-time knobs."""
import os
from pathlib import Path

from dotenv import load_dotenv

_ENV_FILE = os.environ.get("BGP_TRACER_ENV_FILE", ".env").strip() or ".env"
load_dotenv(Path(__file__).parent / _ENV_FILE, override=True)

PROJECT_ROOT = Path(__file__).resolve().parent

DATA_DIR = PROJECT_ROOT / "data"
UPDATES_DIR = DATA_DIR / "updates_rrc00"
PREFIX2AS_DIR = DATA_DIR / "prefix2as"
ASREL_DIR = DATA_DIR / "asrel"
ASORG_DIR = DATA_DIR / "as2org"
RPKI_DATA_DIR = DATA_DIR / "rpki"
LOG_LEVEL = "DEBUG"
LOG_FILE = str(PROJECT_ROOT / "logs" / "bgp_tracer.log")

# ── External data sources ──────────────────────────────────────────────────
RIPE_RIS_URL = "https://data.ris.ripe.net/rrc00/"
RIPE_RPKI_URL = "https://ftp.ripe.net/rpki"
DOWNLOAD_TIMEOUT = 300
GZ_MIN_SIZE = 50000

CLOUDFLARE_HTTP_TIMESERIES_AS_URL = "https://api.cloudflare.com/client/v4/radar/http/timeseries"
#: The DNS resolver timeseries.  This is a *different* data source from
#: the HTTP one: it measures queries to the 1.1.1.1 resolver rather than
#: requests to Cloudflare-served websites, and it is the only Radar
#: series that shows an impact on the 1.1.1.1 service itself.
CLOUDFLARE_DNS_TIMESERIES_URL = "https://api.cloudflare.com/client/v4/radar/dns/timeseries"
CLOUDFLARE_API_TOKEN = (
    os.environ.get("CLOUDFLARE_API_TOKEN")
    or os.environ.get("CLOUDFLARE_API_KEY")
    or ""
).strip()
CLOUDFLARE_DEFAULT_AGG_INTERVAL = "15m"
#: The read timeout.  A shared-span fetch covers five weeks of 15-minute
#: samples, and Radar takes a while to build that; a 10-second timeout
#: cut the request off before it finished.
CLOUDFLARE_TIMEOUT = int(os.environ.get("CLOUDFLARE_TIMEOUT", "60"))
CLOUDFLARE_RADAR_LOCATION = os.environ.get("CLOUDFLARE_RADAR_LOCATION", "").strip()
CLOUDFLARE_RADAR_NORMALIZATION = os.environ.get("CLOUDFLARE_RADAR_NORMALIZATION", "MIN0_MAX").strip()

# ── LLM endpoints ──────────────────────────────────────────────────────────
BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://uni-api.cstcloud.cn/v1")
MODEL = os.environ.get("OPENAI_MODEL", "qwen3.5")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "").strip()
API_KEY = OPENAI_API_KEY

CSTCLOUD_BASE_URL = os.environ.get("CSTCLOUD_BASE_URL", "https://api.kimi.com/coding/v1")
CSTCLOUD_TOKEN = (
    os.environ.get("CSTCLOUD_TOKEN")
    or os.environ.get("CstCloudToken")
    or ""
).strip()
CSTCLOUD_MODEL = os.environ.get("CSTCLOUD_MODEL", "kimi-for-coding")

LLM_THINKING_DISABLE = os.environ.get("LLM_THINKING_DISABLE", "").strip()
LLM_FORCE_KIMI_TEMP = os.environ.get("LLM_FORCE_KIMI_TEMP", "true").lower() == "true"

# ── Elasticsearch (MITM/forge telemetry) ───────────────────────────────────
ES_HOST = os.environ.get("ES_HOST", "http://10.200.23.2:9200")
ES_PORT = int(os.environ.get("ES_PORT", "9200"))
ES_USE_SSL = os.environ.get("ES_USE_SSL", "false").lower() == "true"
ES_VERIFY_CERTS = os.environ.get("ES_VERIFY_CERTS", "false").lower() == "true"
ES_USER = os.environ.get("ES_USER")
ES_PASSWORD = os.environ.get("ES_PASSWORD")
ES_INDEX_NAME = "bgp_messages_traffic_outage"
ES_ENABLED = os.environ.get("ES_ENABLED", "false").lower() == "true"
USE_ES_FOR_CONN_FREQ = os.environ.get("USE_ES_FOR_CONN_FREQ", "false").lower() == "true"

# ── Workflow / ReAct engine ────────────────────────────────────────────────
WORKFLOW_SKIP_WHEN_NO_ANOMALIES = os.environ.get("WORKFLOW_SKIP_WHEN_NO_ANOMALIES", "true").lower() == "true"
WORKFLOW_MIN_HCAF_TIER = os.environ.get("WORKFLOW_MIN_HCAF_TIER", "C1").upper()
WORKFLOW_MIN_HCAF_SCORE = float(os.environ.get("WORKFLOW_MIN_HCAF_SCORE", "0.5"))
WORKFLOW_TOTAL_TIMEOUT_S = float(os.environ.get("BGP_TRACER_WORKFLOW_TIMEOUT_S", "2400.0"))
BUFFER_HOURS = float(os.environ.get("BUFFER_HOURS", "2.0"))

REACT_MAX_ROUNDS = int(os.environ.get("REACT_MAX_ROUNDS", "6"))
REACT_STREAMING_ENABLED = os.environ.get("REACT_STREAMING_ENABLED", "true").lower() == "true"
REACT_LLM_TEMPERATURE = float(os.environ.get("REACT_LLM_TEMPERATURE", "0.1"))

# ── Report LLM call ────────────────────────────────────────────────────────
REPORT_LLM_TIMEOUT_S = float(os.environ.get("REPORT_LLM_TIMEOUT_S", "1500.0"))
REPORT_LLM_RETRIES = int(os.environ.get("REPORT_LLM_RETRIES", "4"))
REPORT_LLM_RETRY_BACKOFF_S = float(os.environ.get("REPORT_LLM_RETRY_BACKOFF_S", "20.0"))
REPORT_MAX_TOKENS = int(os.environ.get("REPORT_MAX_TOKENS", "4000"))
REPORT_REQUIRE_LLM = os.environ.get("REPORT_REQUIRE_LLM", "0").strip().lower() in ("1", "true", "yes")
REPORT_USE_DETERMINISTIC = os.environ.get("REPORT_USE_DETERMINISTIC", "1").strip().lower() in ("1", "true", "yes")
REPORT_PAYLOAD_MAX_CHARS = int(os.environ.get("REPORT_PAYLOAD_MAX_CHARS", "30000"))

# ── HCAF causal attribution thresholds ────────────────────────────────────
# NOTE (2026-10-28): the per-channel HCAF_WEIGHTS_* / HCAF_MAJORITY_THRESHOLD
# weighted-vote scheme was retired with the Granger decision channel. The
# synthesis is now CSS-anchored Bayesian (see agents/css_engine.py).

# Abstention floor for causal *direction*.
# BUG (2026-10-05): when the three innovation methods all abstain (no
# significant breakpoint, no cascade evidence, and CSS declining to commit)
# the pipeline still emitted a concrete direction with confidence ~0.06. On the v13 ground
# truth every such event had `routing_withdrawal_count == 0` and no routing
# evidence at all, so the direction was pure noise — but it was reported as a
# confident verdict. Ground-truth review precision sat at 0.552.
# An "unknown" verdict is already accepted as non-error by the evaluation
# harness, so abstaining on genuinely evidence-free input is strictly more
# honest and strictly scores better. Raise the floor to force a direction only
# when the evidence supports one.
# DEPRECATED (2026-10-22): this floor was applied to the *blended display
# score* (0.6*css_conf + 0.3*innovation + 0.1*TE, times a 0.7/0.95 causal
# factor), which lives on a different scale from the quantity it was meant to
# threshold.  It is kept only so old callers/imports keep working and MUST NOT
# be used as a decision gate.  See HCAF_MIN_POSTERIOR below.
HCAF_MIN_DIRECTION_CONFIDENCE = float(
    os.environ.get("BGP_TRACER_HCAF_MIN_DIRECTION_CONF", "0.55")
)

# Abstention floor for causal *direction*, applied to the Bayesian posterior
# mass of the dominant hypothesis (the quantity the synthesis actually
# produces).  A direction is only committed when max(posterior) reaches this
# value; the three-way posterior sums to 1, so 0.50 means "the dominant
# hypothesis outweighs the other two combined".
HCAF_MIN_POSTERIOR = float(
    os.environ.get("BGP_TRACER_HCAF_MIN_POSTERIOR", "0.50")
)

# ── Detector thresholds ────────────────────────────────────────────────────
DEFAULT_LEAK_THRESHOLD = 0.4
DEFAULT_FORGE_THRESHOLD = 0.001
DEFAULT_ANOMALY_THRESHOLD = 0.2
SKIP_FORGE_DETECTION = True
PATHPROB_FILE = PROJECT_ROOT / "detectors" / "leak" / "pathprob" / "pathprob.txt"
PATHPROB_AE_ROOT = os.environ.get("PATHPROB_AE_ROOT", "/data/PathProb").strip()
PATHPROB_SEARCH_PATHS = [
    PATHPROB_FILE,
    Path(PATHPROB_AE_ROOT) / "test_data" / "prob_inference" / "result" / "202506" / "pathprob.txt",
]

MAX_WORKERS = int(os.environ.get("BGP_TRACER_MAX_WORKERS", "8"))
IO_BUSY_THRESHOLD = 70

# ── Auxiliary WHOIS / PDNS APIs ─────────────────────────────────────────────
RIPESTAT_TOKEN = os.environ.get("RIPESTAT_TOKEN", "").strip()
CIRCL_PDNS_URL = "https://www.circl.lu/pdns/query"
BGPVIEW_BASE = "https://api.bgpview.io"
RIPE_DB_WHOIS_USERNAME = os.environ.get("RIPE_DB_WHOIS_USERNAME", "").strip()
RIPE_DB_WHOIS_PASSWORD = os.environ.get("RIPE_DB_WHOIS_PASSWORD", "").strip()

# ── Top-level feature flags ────────────────────────────────────────────────
MITM_DETECTION_ENABLED = os.environ.get("MITM_DETECTION_ENABLED", "false").lower() == "true"
JSON_OUTPUT_ENABLED = os.environ.get("JSON_OUTPUT_ENABLED", "false").lower() in ("true", "1", "yes")
