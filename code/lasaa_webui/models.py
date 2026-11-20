# <legal>
# LASAA tool
#
# Copyright 2026 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS
# TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE
# OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Licensed under a MIT (SEI)-style license, please see License.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM26-0426
# </legal>
"""The models the run form offers, how to call each one's LLM client, and prices.

A model "spec" is what the run form's Model panel says, as a dict:
provider (one of PROVIDERS), model, effort, region and prefix (AWS
Bedrock), base_url, api_type, and api_key_name (Other), or_endpoint
(OpenRouter), max_output_tokens, flex (OpenAI), and concurrency.  Only
some of it decides which replies can be reused (config_of()); the rest
only changes how the client gets them (client_args()).

Prices come from code/model_prices.csv, reread on each use.  Its columns are
model, provider, input_usd_per_million_tokens, output_usd_per_million_tokens,
pricing_tier, source_url, accessed_utc.  Cached input tokens are charged at
the full input price, so cost figures err high.
"""

import csv
import ipaddress
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

CODE_DIR = Path(__file__).resolve().parent.parent
PRICES_CSV = CODE_DIR / "model_prices.csv"

PROVIDERS = ("OpenAI", "AWS Bedrock", "Fireworks", "Gemini", "OpenRouter", "Other")
CLIENTS = ("ask_gpt.py", "ask_claude_aws.py")
EFFORTS = ("", "low", "medium", "high")                    # "" is the client's default
API_TYPES = ("", "chat_completion", "response")            # "" is ask_gpt.py's choice
BEDROCK_REGIONS = ("us-east-1", "us-east-2", "us-west-1", "us-west-2",
                   "us-gov-east-1", "us-gov-west-1")
BEDROCK_PREFIXES = ("us.", "us-gov.", "global.")           # cross-region inference profiles
DEFAULT_CONCURRENCY = 200
# The environment variable with each provider's API key (Other: api_key_name,
# which must end in KEY_SUFFIX, so that no other secret can be sent to a URL
# typed into the form).  AWS Bedrock uses the AWS credential chain.
PROVIDER_KEYS = {"OpenAI": "OPENAI_API_KEY", "Fireworks": "FIREWORKS_API_KEY",
                 "Gemini": "GEMINI_API_KEY", "OpenRouter": "OPENROUTER_API_KEY"}
KEY_SUFFIX = "_LASAA_KEY"
# The clients' own output-token caps when none is given (ask_gpt.py,
# ask_claude_aws.py); others have none.
DEFAULT_OUTPUT_CAPS = {"Fireworks": 64000, "OpenRouter": 64000, "AWS Bedrock": 60000}
# The ready-made models at the top of the form's list.
MODELS = [
    {"provider": "OpenAI", "model": "gpt-6-luna"},
    {"provider": "OpenAI", "model": "gpt-6-sol"},
    {"provider": "AWS Bedrock", "model": "claude-haiku-5-5"},
    {"provider": "AWS Bedrock", "model": "claude-sonnet-5-5"},
    {"provider": "AWS Bedrock", "model": "claude-opus-5-5"},
    {"provider": "Fireworks", "model": "gpt-oss-120b"},
]
# Which model_prices.csv providers count as each provider's prices.
PRICE_PROVIDERS = {"OpenAI": ("openai",), "AWS Bedrock": ("anthropic", "aws", "bedrock"),
                   "Fireworks": ("fireworks",), "Gemini": ("google", "gemini"),
                   "OpenRouter": ("openrouter",), "Other": ()}
MODEL_PREFIXES = ("us.anthropic.", "us-gov.anthropic.", "global.anthropic.", "anthropic.",
                  "accounts/fireworks/models/")
SPEC_FIELDS = ("provider", "model", "effort", "region", "prefix", "base_url", "api_type",
               "api_key_name", "or_endpoint", "max_output_tokens", "flex", "concurrency")


def new_spec(**kw):
    spec = {"provider": "OpenAI", "model": "", "effort": "", "region": BEDROCK_REGIONS[0],
            "prefix": "", "base_url": "", "api_type": "", "api_key_name": "", "or_endpoint": "",
            "max_output_tokens": None, "flex": False, "concurrency": DEFAULT_CONCURRENCY}
    spec.update(kw)
    return spec


def client_of(spec):
    return "ask_claude_aws.py" if spec["provider"] == "AWS Bedrock" else "ask_gpt.py"


def bedrock_prefix(region):
    """The cross-region inference prefix that goes with *region*."""
    if region.startswith("us-gov-"):
        return "us-gov."
    if region.startswith("us-"):
        return "us."
    m = re.match(r"^(eu|ap)-", region)
    return {"eu": "eu.", "ap": "apac."}[m.group(1)] if m else "global."


def bedrock_model(name):
    """"anthropic.NAME" for a Bedrock model name given as NAME, anthropic.NAME,
    or PREFIX.anthropic.NAME: the region prefix doesn't change the model."""
    m = re.match(r"^(?:[a-z-]+\.)?anthropic\.(.+)$", name)
    return "anthropic." + (m.group(1) if m else name)


def validate(spec):
    """Check *spec* (raises ValueError) and fill in what follows from it."""
    p = spec["provider"]
    if p not in PROVIDERS:
        raise ValueError("Choose a provider.")
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$", spec["model"] or ""):
        raise ValueError("Give the model's name (letters, digits, and . _ : / @ + -).")
    if spec["effort"] not in EFFORTS:
        raise ValueError("Unknown reasoning effort.")
    if not isinstance(spec["concurrency"], int) or not 1 <= spec["concurrency"] <= 1000:
        raise ValueError("Concurrency must be a whole number from 1 to 1000.")
    if spec["max_output_tokens"] is not None and (
            not isinstance(spec["max_output_tokens"], int) or spec["max_output_tokens"] < 1):
        raise ValueError("Max output tokens must be a whole number of at least 1.")
    if p == "AWS Bedrock":
        if not re.match(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", spec["region"] or ""):
            raise ValueError("Give an AWS region such as us-east-1.")
        if not spec["prefix"]:
            spec["prefix"] = bedrock_prefix(spec["region"])
        if spec["prefix"] != "none" and not re.match(r"^[a-z][a-z-]*\.$", spec["prefix"]):
            raise ValueError('A model prefix looks like "us." (or "none" for none).')
        spec["model"] = bedrock_model(spec["model"])
    if p == "Other":
        if not re.match(r"^https?://[^\s/?#]+[^\s]*$", spec["base_url"] or ""):
            raise ValueError("Give the endpoint's base URL (http:// or https://).")
        if spec["api_type"] not in API_TYPES:
            raise ValueError("Unknown API type.")
        if not re.match(r"^[A-Z][A-Z0-9_]*" + KEY_SUFFIX + "$", spec["api_key_name"] or ""):
            raise ValueError(f"The API key's environment variable must be named "
                             f"SOMETHING{KEY_SUFFIX}.")
    if p == "OpenRouter" and not re.match(r"^[A-Za-z0-9._/-]+$", spec["or_endpoint"] or ""):
        raise ValueError("OpenRouter needs an endpoint tag (e.g. crusoe/bf16); "
                         "test the connection with it empty to list them.")
    return spec


def config_of(spec):
    """The part of *spec* that decides which replies can be reused: a run's
    output directory (its cache) is per (client, model, effort, endpoint).
    The endpoint is "" (OpenAI, AWS Bedrock), the provider (Fireworks,
    Gemini), "OpenRouter:" plus the endpoint tag (which can be another
    quantization), or the base URL (Other).  A Bedrock model is kept
    without its region prefix."""
    p = spec["provider"]
    endpoint = {"OpenAI": "", "AWS Bedrock": "", "Fireworks": "Fireworks", "Gemini": "Gemini",
                "OpenRouter": f"OpenRouter:{spec['or_endpoint']}",
                "Other": spec["base_url"]}[p]
    return {"client": client_of(spec), "model": spec["model"], "effort": spec["effort"],
            "endpoint": endpoint}


def is_local_url(url):
    """Whether *url*'s host is "localhost" or a numeric IP address, as for
    mock_llm_server.py, which needs to know which trial each request is for
    (ask_gpt.py's --mock-llm-server).  Other servers ignore the header."""
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return False
    if host == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def client_args(spec):
    """The arguments that adjudicate_alerts.py passes on to the client (after --)."""
    p = spec["provider"]
    model = spec["model"]
    if p == "AWS Bedrock" and spec["prefix"] != "none":
        model = spec["prefix"] + model
    args = ["--model", model]
    if spec["effort"]:
        args += ["--reasoning-effort", spec["effort"]]
    if p == "AWS Bedrock":
        args += ["--region-name", spec["region"]]
    elif p in ("Fireworks", "Gemini", "OpenRouter"):
        args += ["--provider", p]
    if p == "OpenRouter":
        args += ["--or-endpoint", spec["or_endpoint"]]
    if p == "Other":
        args += ["--base-url", spec["base_url"], "--api-key-name", spec["api_key_name"]]
        if spec["api_type"]:
            args += ["--api-type", spec["api_type"]]
        if is_local_url(spec["base_url"]):
            args.append("--mock-llm-server")
    if p == "OpenAI" and spec["flex"]:
        args.append("--flex-tier")
    if spec["max_output_tokens"]:
        args += ["--max-output-tokens", str(spec["max_output_tokens"])]
    if spec["concurrency"] != DEFAULT_CONCURRENCY:
        args += ["--concurrency", str(spec["concurrency"])]
    return args


def output_cap(spec):
    """The output-token cap the client will use, or None for none."""
    return spec["max_output_tokens"] or DEFAULT_OUTPUT_CAPS.get(spec["provider"])


def key_var(spec):
    """The environment variable the API key comes from (None: AWS credentials)."""
    if spec["provider"] == "Other":
        return spec["api_key_name"]
    return PROVIDER_KEYS.get(spec["provider"])


def short_name(spec):
    """The model as people call it: without Bedrock's prefixes."""
    return re.sub(r"^anthropic\.", "", spec["model"])


def label(spec):
    """E.g. "gpt-oss-120b (via OpenRouter, crusoe/bf16)"."""
    via = spec["provider"]
    if via == "OpenRouter" and spec["or_endpoint"]:
        via += ", " + spec["or_endpoint"]
    elif via == "Other" and spec["base_url"]:
        via = re.sub(r"^https?://", "", spec["base_url"]).split("/")[0]
    return f"{short_name(spec)} (via {via})"


def load_prices(path=PRICES_CSV):
    """{model: [{"input": $/Mtok, "output": $/Mtok, "provider", "source", "as_of"}, ...]}."""
    prices = {}
    try:
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    prices.setdefault(row["model"].strip(), []).append({
                        "input": float(row["input_usd_per_million_tokens"]),
                        "output": float(row["output_usd_per_million_tokens"]),
                        "provider": (row.get("provider") or "").strip(),
                        "source": row.get("source_url") or "",
                        "as_of": row.get("accessed_utc") or ""})
                except (KeyError, TypeError, ValueError):
                    continue
    except OSError:
        pass
    return prices


def price_for(model, prices, provider=None):
    """The price row for *model* (allowing for provider prefixes and dated
    names), from *provider* if model_prices.csv has a row for it, else any."""
    name = model or ""
    for p in MODEL_PREFIXES:
        if name.startswith(p):
            name = name[len(p):]
    if name not in prices:
        dated = sorted(k for k in prices
                       if k.startswith(name + "-") and k[len(name) + 1:][:1].isdigit())
        if not dated:
            return None
        name = dated[0]
    rows = prices[name] if isinstance(prices[name], list) else [prices[name]]
    aliases = PRICE_PROVIDERS.get(provider, ())
    for row in rows:
        if any(re.sub(r"[^a-z]", "", row.get("provider", "").lower()).startswith(a)
               for a in aliases):
            return row
    return rows[0]


def cost(price, input_tokens, output_tokens):
    if price is None:
        return None
    return (input_tokens * price["input"] + output_tokens * price["output"]) / 1e6
