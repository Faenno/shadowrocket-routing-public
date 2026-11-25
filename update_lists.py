"""Generate Shadowrocket rule sets from itdoginfo/allow-domains."""

import argparse
from http.client import HTTPException
import ipaddress
from pathlib import Path
import re
from shutil import copy2
import sys
from tempfile import TemporaryDirectory
from urllib.request import urlopen

UPSTREAM_RAW_URL = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
NETWORK_PREFIX = re.compile(r"(?:0|[1-9][0-9]*)")

DOMAIN_SOURCE_PATHS = (
    "Russia/inside-raw.lst",
    "Categories/hodca.lst",
    "Services/cloudflare.lst",
    "Services/discord.lst",
    "Services/google_ai.lst",
    "Services/google_play.lst",
    "Services/meta.lst",
    "Services/telegram.lst",
    "Services/twitter.lst",
)

# Keep service CIDRs even when they overlap a hosting provider's network.
SUBNET_SOURCE_PATHS = (
    "Subnets/IPv4/discord.lst",
    "Subnets/IPv4/meta.lst",
    "Subnets/IPv4/telegram.lst",
    "Subnets/IPv4/twitter.lst",
    "Subnets/IPv6/discord.lst",
    "Subnets/IPv6/meta.lst",
    "Subnets/IPv6/telegram.lst",
    "Subnets/IPv6/twitter.lst",
)


def read_source(path, source_dir):
    if source_dir is not None:
        with (source_dir / path).open("rb") as source:
            data = source.read(MAX_SOURCE_BYTES + 1)
    else:
        with urlopen(f"{UPSTREAM_RAW_URL}/{path}", timeout=30) as source:
            data = source.read(MAX_SOURCE_BYTES + 1)
            content_length = source.headers.get("Content-Length")
            if content_length is not None and len(data) < int(content_length):
                raise ValueError("incomplete download")

    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("source exceeds the size limit")
    return data.decode("utf-8-sig")


def read_entries(path, source_dir):
    try:
        source = read_source(path, source_dir)
    except (HTTPException, OSError, ValueError) as error:
        raise ValueError(f"{path}: {error}") from error

    entries = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        value = line.partition("#")[0].strip()
        if value:
            entries.append((line_number, value))
    if not entries:
        raise ValueError(f"{path}: no entries")
    return entries


def normalize_domain(value):
    # Upstream uses a leading dot for a suffix such as .ua.
    explicit_suffix = value.startswith(".")
    domain = value.removeprefix(".").removesuffix(".")
    try:
        domain = domain.encode("idna").decode("ascii").lower()
        # Decode A-labels too so malformed punycode is rejected.
        domain.encode("ascii").decode("idna")
    except UnicodeError as error:
        raise ValueError("invalid IDNA domain") from error

    labels = domain.split(".")
    if (
        len(domain) > 253
        or any(not DOMAIN_LABEL.fullmatch(label) for label in labels)
        or not labels[-1][:1].isalpha()
        or (len(labels) == 1 and not explicit_suffix)
    ):
        raise ValueError("invalid domain suffix")
    return domain


def normalize_network(value, version):
    address, _, prefix = value.partition("/")
    if not NETWORK_PREFIX.fullmatch(prefix) or "%" in address:
        raise ValueError("expected an address with a numeric CIDR prefix")

    network = ipaddress.ip_network(value, strict=True)
    if network.version != version:
        raise ValueError(f"expected an IPv{version} network")
    return network


def build_lists(source_dir=None):
    domains = set()
    for path in DOMAIN_SOURCE_PATHS:
        for line_number, value in read_entries(path, source_dir):
            try:
                domains.add(normalize_domain(value))
            except ValueError as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error

    networks = set()
    for path in SUBNET_SOURCE_PATHS:
        version = 4 if path.startswith("Subnets/IPv4/") else 6
        for line_number, value in read_entries(path, source_dir):
            try:
                networks.add(normalize_network(value, version))
            except ValueError as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error

    domain_rules = [f"DOMAIN-SUFFIX,{domain}\n" for domain in sorted(domains)]
    subnet_rules = []
    for network in sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen)):
        rule_type = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        subnet_rules.append(f"{rule_type},{network},no-resolve\n")
    return {
        "domains.list": "".join(domain_rules),
        "subnets.list": "".join(subnet_rules),
        "podkop.list": "".join(domain_rules + subnet_rules),
    }


def write_lists(lists, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix=".shadowrocket-", dir=output_dir) as staging_dir:
        staging_dir = Path(staging_dir)
        backup_dir = staging_dir / "previous"
        backup_dir.mkdir()
        for name, contents in lists.items():
            (staging_dir / name).write_text(contents, encoding="utf-8", newline="\n")
            target = output_dir / name
            if target.exists() or target.is_symlink():
                copy2(target, backup_dir / name, follow_symlinks=False)

        replaced = []
        try:
            for name in lists:
                (staging_dir / name).replace(output_dir / name)
                replaced.append(name)
        except OSError:
            for name in reversed(replaced):
                backup = backup_dir / name
                if backup.exists() or backup.is_symlink():
                    backup.replace(output_dir / name)
                else:
                    (output_dir / name).unlink()
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, help="Read a local snapshot instead of downloading.")
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)

    try:
        lists = build_lists(args.source_dir)
        write_lists(lists, args.output_dir)
    except (OSError, ValueError) as error:
        print(f"Update failed: {error}", file=sys.stderr)
        return 1

    for name, contents in lists.items():
        print(f"{name}: {len(contents.splitlines())} rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
