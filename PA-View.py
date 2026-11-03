#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PA-View - read-only Palo Alto Networks PAN-OS XML configuration viewer.

The tool reads an exported PAN-OS configuration XML and generates a self-contained
HTML report. It does not connect to or modify a firewall.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import traceback
import webbrowser
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

APP_VERSION = "2.1.0"
DEFAULT = "N/A"


def esc(value: Any) -> str:
    """HTML-escape any value (safe replacement for the original escape_html)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def escape_html(value: Any) -> str:
    """Backward-compatible alias retained from PA-View 1.x."""
    return esc(value)


def _clean(value: Any, default: str = DEFAULT) -> str:
    if value is None:
        return default
    value = str(value).strip()
    return value if value else default


def get_text(element: ET.Element | None, path: str, default: str = DEFAULT) -> str:
    """Return text at an XML path; tolerate absent and whitespace-only elements."""
    if element is None:
        return default
    try:
        node = element.find(path)
    except (SyntaxError, TypeError):
        return default
    if node is None:
        return default
    return _clean(node.text, default)


def get_members(element: ET.Element | None, path: str, default: str = "any") -> str:
    """Return PAN-OS member values, with support for name attributes."""
    if element is None:
        return default
    try:
        nodes = element.findall(f"{path}/member")
    except (SyntaxError, TypeError):
        return default
    values = []
    for node in nodes:
        value = _clean(node.text, "")
        if not value:
            value = _clean(node.attrib.get("name"), "")
        if value:
            values.append(value)
    return ", ".join(dict.fromkeys(values)) if values else default


def _entry_value(node: ET.Element) -> str:
    return _clean(node.attrib.get("name") or node.text, "")


def _entry_values(element: ET.Element | None, path: str) -> list[str]:
    if element is None:
        return []
    try:
        nodes = element.findall(path)
    except (SyntaxError, TypeError):
        return []
    return list(dict.fromkeys(v for v in (_entry_value(n) for n in nodes) if v))


def _unique_nodes(root: ET.Element, paths: Iterable[str]) -> list[ET.Element]:
    """Collect nodes from alternative schema paths without duplicate elements."""
    result: list[ET.Element] = []
    seen: set[int] = set()
    for path in paths:
        try:
            nodes = root.findall(path)
        except SyntaxError:
            nodes = []
        for node in nodes:
            marker = id(node)
            if marker not in seen:
                seen.add(marker)
                result.append(node)
    return result


def _first(root: ET.Element, paths: Iterable[str]) -> ET.Element | None:
    for path in paths:
        node = root.find(path)
        if node is not None:
            return node
    return None


def _join(values: Iterable[str], default: str = "N/A") -> str:
    items = list(dict.fromkeys(v for v in values if v and v != "N/A"))
    return ", ".join(items) if items else default


def _bool_text(element: ET.Element | None, path: str, default: str = "no") -> bool:
    value = get_text(element, path, default).strip().lower()
    return value in {"yes", "true", "1", "enabled"}


def _members_from(node: ET.Element | None, paths: Iterable[str]) -> str:
    values: list[str] = []
    for path in paths:
        value = get_members(node, path, "")
        if value:
            values.extend(v.strip() for v in value.split(",") if v.strip())
    return _join(values)


def _parse_interface(node: ET.Element, interface_type: str, name: str | None = None,
                     inferred_mode: str | None = None) -> dict[str, str]:
    """Read one interface entry without accidentally inheriting child-unit IPs."""
    interface_name = name or node.attrib.get("name", "N/A")
    mode_nodes = [mode for mode in ("layer3", "layer2", "virtual-wire", "ha", "aggregate-group")
                  if node.find(f"./{mode}") is not None]
    mode = ", ".join(mode_nodes) if mode_nodes else (inferred_mode or ("layer3" if node.find("./ip") is not None else "Not set"))

    ip_values: list[str] = []
    for path in ("./layer3/ip/entry", "./ip/entry"):
        ip_values.extend(_entry_values(node, path))
    ip_text = _join(ip_values)

    mgmt = _join([
        get_text(node, "./layer3/interface-management-profile", ""),
        get_text(node, "./layer2/interface-management-profile", ""),
        get_text(node, "./interface-management-profile", ""),
    ])
    mtu = _join([
        get_text(node, "./layer3/mtu", ""),
        get_text(node, "./layer2/mtu", ""),
        get_text(node, "./mtu", ""),
    ], "Default")

    tag = get_text(node, "./tag", "None")
    if tag == "None":
        tag = get_text(node, "./vlan-tag", "None")

    return {
        "name": interface_name,
        "type": interface_type,
        "mode": mode,
        "ip": ip_text,
        "mgmt": mgmt,
        "mtu": mtu,
        "vlan": tag,
        "comment": get_text(node, "./comment", ""),
        "link_state": get_text(node, "./link-state", "N/A"),
        "speed": get_text(node, "./link-speed", "N/A"),
        "duplex": get_text(node, "./link-duplex", "N/A"),
    }


def _parse_config(xml_file_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Parse the exported config into a normalized, JSON-serializable model."""
    path = Path(xml_file_path).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    # PAN-OS exports are normally namespace-free XML. Reject DTD/entity declarations
    # before parsing to avoid unsafe XML entity expansion on untrusted input.
    with path.open("rb") as source:
        tail = b""
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            scan = (tail + chunk).upper()
            if b"<!DOCTYPE" in scan or b"<!ENTITY" in scan:
                raise ValueError("The file contains a DTD/ENTITY declaration. Import was aborted for security reasons.")
            tail = scan[-16:]

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse XML: {exc}") from exc
    root = tree.getroot()

    # --- DEVICE / MANAGEMENT ---
    system = _first(root, [".//devices/entry/deviceconfig/system", ".//deviceconfig/system"])
    ha = _first(root, [".//devices/entry/deviceconfig/high-availability", ".//deviceconfig/high-availability"])
    dns = system.find("./dns-setting/servers") if system is not None else None
    device_info = {
        "hostname": get_text(system, "./hostname"),
        "domain": get_text(system, "./domain", ""),
        "ip_address": get_text(system, "./ip-address"),
        "netmask": get_text(system, "./netmask"),
        "default_gateway": get_text(system, "./default-gateway"),
        "dns_primary": get_text(dns, "./primary"),
        "dns_secondary": get_text(dns, "./secondary"),
        "panorama_server": get_text(system, "./panorama-server"),
        "ha_enabled": "Yes" if ha is not None else "No",
        "ha_peer_ip": get_text(ha, "./interface/ha1/peer-ip") if ha is not None else "N/A",
        "ha1_ip": get_text(ha, "./interface/ha1/ip-address") if ha is not None else "N/A",
        "timezone": get_text(system, "./timezone"),
        "locale": get_text(system, "./locale"),
        "login_banner": get_text(system, "./login-banner", "Not configured"),
        "ssl_tls_profile": get_text(system, "./ssl-tls-service-profile", "N/A"),
        "permitted_ip": [v.strip() for v in get_members(system, "./permitted-ip", "").split(",") if v.strip()],
        "ssh_enabled": get_text(system, "./services/ssh", "N/A"),
        "telemetry": get_text(system, "./device-telemetry/enable", "N/A"),
    }
    # Read management services from PAN-OS system/services without relying on
    # runtime values that are not part of the exported configuration.
    services_node = system.find("./services") if system is not None else None
    management_services = []
    if services_node is not None:
        for child in list(services_node):
            if child.tag in {"service-route", "uid-agent", "global-protect-data-file", "snmp", "ssh", "https", "http", "telnet"}:
                management_services.append({"service": child.tag, "value": _clean(child.text, "Configured")})

    admins: list[dict[str, str]] = []
    for user in _unique_nodes(root, [".//mgt-config/users/entry"]):
        role_node = user.find("./permissions/role-based/superuser")
        role = "Superuser" if role_node is not None else get_text(user, "./permissions/role-based/custom/profile", "Role-Based")
        if user.find("./permissions/role-based") is None and user.find("./permissions") is not None:
            role = "Role-Based"
        admins.append({
            "name": user.attrib.get("name", "N/A"),
            "role": role,
            "password_profile": get_text(user, "./password-profile", "N/A"),
            "phash_present": "Yes" if user.find("./phash") is not None else "No/Not exported",
        })

    # --- NETWORK ---
    interfaces: list[dict[str, str]] = []
    interface_paths = [
        (".//network/interface/ethernet/entry", "Ethernet"),
        (".//network/interface/aggregate-ethernet/entry", "Aggregate Ethernet"),
    ]
    for xpath, kind in interface_paths:
        for entry in _unique_nodes(root, [xpath]):
            interfaces.append(_parse_interface(entry, kind))
            parent_name = entry.attrib.get("name", "")
            for unit_path in ("./layer3/units/entry", "./layer2/units/entry", "./units/entry"):
                for unit in entry.findall(unit_path):
                    inferred = "layer3" if "layer3" in unit_path else "layer2" if "layer2" in unit_path else None
                    interfaces.append(_parse_interface(unit, "Subinterface", unit.attrib.get("name") or parent_name, inferred))

    for if_type in ("loopback", "tunnel", "vlan"):
        entries = _unique_nodes(root, [f".//network/interface/{if_type}/units/entry", f".//network/interface/{if_type}/entry"])
        for entry in entries:
            interfaces.append(_parse_interface(entry, if_type.capitalize()))

    # De-duplicate interfaces by their configured name and type.
    interfaces = list({(i["name"], i["type"]): i for i in interfaces}.values())

    zones: list[dict[str, str]] = []
    for zone in _unique_nodes(root, [".//vsys/entry/zone/entry", ".//shared/zone/entry"]):
        modes = [m for m in ("layer3", "layer2", "virtual-wire", "tap", "external") if zone.find(f"./network/{m}") is not None]
        all_ifaces = []
        for mode in ("layer3", "layer2", "virtual-wire", "tap", "external"):
            all_ifaces.extend(v for v in get_members(zone, f"./network/{mode}", "").split(",") if v.strip())
        zones.append({
            "name": zone.attrib.get("name", "N/A"),
            "type": ", ".join(modes) if modes else "Other",
            "interfaces": _join(all_ifaces),
            "enable_user_id": get_text(zone, "./enable-user-identification", "N/A"),
        })

    routers: list[dict[str, Any]] = []
    for vr in _unique_nodes(root, [".//network/virtual-router/entry"]):
        routes = []
        for route in vr.findall(".//routing-table/ip/static-route/entry"):
            nh = get_text(route, "./nexthop/ip-address", get_text(route, "./nexthop/interface", get_text(route, "./nexthop/discard", "N/A")))
            routes.append({
                "name": route.attrib.get("name", "N/A"),
                "destination": get_text(route, "./destination"),
                "nexthop": nh,
                "interface": get_text(route, "./interface", "N/A"),
                "metric": get_text(route, "./metric", "N/A"),
                "description": get_text(route, "./route-table", ""),
            })
        bgp_id = get_text(vr, ".//protocol/bgp/router-id", "N/A")
        ospf_id = get_text(vr, ".//protocol/ospf/router-id", "N/A")
        protocols = []
        if bgp_id != "N/A":
            protocols.append(f"BGP (ID: {bgp_id})")
        if ospf_id != "N/A":
            protocols.append(f"OSPF (ID: {ospf_id})")
        if vr.find(".//protocol/ospfv3") is not None:
            protocols.append("OSPFv3")
        if vr.find(".//protocol/rip") is not None:
            protocols.append("RIP")
        routers.append({
            "name": vr.attrib.get("name", "N/A"),
            "interfaces": get_members(vr, "./interface"),
            "routes": routes,
            "protocols": ", ".join(protocols) if protocols else "Static Only",
            "bgp_peer_groups": len(vr.findall(".//protocol/bgp/peer-group/entry")),
            "ospf_areas": len(vr.findall(".//protocol/ospf/area/entry")),
        })

    global_protect = {"portals": [], "gateways": []}
    portal_nodes = _unique_nodes(root, [".//global-protect-portal/entry"])
    gateway_nodes = _unique_nodes(root, [".//global-protect-gateway/entry"])
    for gp in portal_nodes:
        global_protect["portals"].append({
            "name": gp.attrib.get("name", "N/A"),
            "auth_profile": get_text(gp, ".//client-auth/entry/auth-profile", "N/A"),
            "interface": get_text(gp, "./portal-config/local-address/interface", "N/A"),
            "address": get_text(gp, "./portal-config/local-address/ip", "N/A"),
        })
    for gw in gateway_nodes:
        global_protect["gateways"].append({
            "name": gw.attrib.get("name", "N/A"),
            "ip_pool": _members_from(gw, ["./agent-user-override/key", ".//ip-pool"]),
            "interface": get_text(gw, "./local-address/interface", "N/A"),
            "address": get_text(gw, "./local-address/ip", "N/A"),
        })

    # --- VPN / CRYPTO ---
    vpns: dict[str, list[dict[str, str]]] = {"ike": [], "ipsec": [], "crypto_ike": [], "crypto_ipsec": []}
    for ike in _unique_nodes(root, [".//network/ike/gateway/entry"]):
        vpns["ike"].append({
            "name": ike.attrib.get("name", "N/A"),
            "interface": get_text(ike, "./local-address/interface"),
            "local_ip": get_text(ike, "./local-address/ip", "N/A"),
            "peer_ip": get_text(ike, "./peer-address/ip", get_text(ike, "./peer-address/fqdn", "N/A")),
            "version": _join(["IKEv1" if ike.find("./protocol/ikev1") is not None else "", "IKEv2" if ike.find("./protocol/ikev2") is not None else ""]),
            "profile": get_text(ike, "./protocol/ikev1/ike-crypto-profile", get_text(ike, "./protocol/ikev2/ike-crypto-profile", get_text(ike, "./protocol/ikev1/dpd/crypto-profile", "default"))),
            "auth_profile": get_text(ike, "./authentication/profile", "Pre-shared key configured" if ike.find("./authentication/pre-shared-key/key") is not None else "Certificate / other"),
            "passive": get_text(ike, "./passive-mode", "no"),
        })
    for tunnel in _unique_nodes(root, [".//network/tunnel/ipsec/entry"]):
        ike_refs = _reference_values(tunnel, "./auto-key/ike-gateway")
        vpns["ipsec"].append({
            "name": tunnel.attrib.get("name", "N/A"),
            "interface": get_text(tunnel, "./tunnel-monitor/tunnel-interface", "N/A"),
            "ike_gateway": _join(ike_refs),
            "profile": get_text(tunnel, "./auto-key/ipsec-crypto-profile", "default"),
            "proxy_ids": len(tunnel.findall("./auto-key/proxy-id/entry")),
            "monitor": get_text(tunnel, "./tunnel-monitor/enable", "no"),
        })
    for profile in _unique_nodes(root, [".//network/ike/crypto-profile/ike-crypto-profile/entry"]):
        vpns["crypto_ike"].append({
            "name": profile.attrib.get("name", "N/A"),
            "hash": get_members(profile, "./hash"),
            "enc": get_members(profile, "./encryption"),
            "dh": get_members(profile, "./dh-group"),
            "lifetime": get_text(profile, "./lifetime/hours", "N/A"),
        })
    for profile in _unique_nodes(root, [".//network/ike/crypto-profile/ipsec-crypto-profile/entry"]):
        vpns["crypto_ipsec"].append({
            "name": profile.attrib.get("name", "N/A"),
            "auth": get_members(profile, "./esp/authentication"),
            "enc": get_members(profile, "./esp/encryption"),
            "dh": get_members(profile, "./dh-group"),
            "lifetime": get_text(profile, "./lifetime/hours", "N/A"),
        })

    # --- OBJECTS ---
    objects: dict[str, list[dict[str, Any]]] = {
        "addresses": [], "addr_groups": [], "services": [], "svc_groups": [],
        "tags": [], "certs": [], "applications": [],
    }
    for addr in _unique_nodes(root, [".//address/entry"]):
        value = _join([
            get_text(addr, "./ip-netmask", ""), get_text(addr, "./ip-range", ""),
            get_text(addr, "./fqdn", ""), get_text(addr, "./ip-wildcard", ""),
        ])
        objects["addresses"].append({
            "name": addr.attrib.get("name", "N/A"), "value": value,
            "desc": get_text(addr, "./description", ""),
            "tag": get_members(addr, "./tag", ""),
            "type": next((k for k in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard") if addr.find(f"./{k}") is not None), "unknown"),
        })
    for group in _unique_nodes(root, [".//address-group/entry"]):
        objects["addr_groups"].append({
            "name": group.attrib.get("name", "N/A"),
            "members": get_members(group, "./static", ""),
            "dynamic": get_text(group, "./dynamic/filter", ""),
            "type": "Dynamic" if group.find("./dynamic") is not None else "Static",
        })
    for service in _unique_nodes(root, [".//service/entry"]):
        tcp = service.find("./protocol/tcp")
        udp = service.find("./protocol/udp")
        protocol = "TCP" if tcp is not None else "UDP" if udp is not None else "Other"
        proto_node = tcp if tcp is not None else udp
        objects["services"].append({
            "name": service.attrib.get("name", "N/A"),
            "protocol": protocol,
            "port": get_text(proto_node, "./port", "N/A"),
            "source_port": get_text(proto_node, "./source-port", "any"),
            "description": get_text(service, "./description", ""),
        })
    for group in _unique_nodes(root, [".//service-group/entry"]):
        objects["svc_groups"].append({"name": group.attrib.get("name", "N/A"), "members": get_members(group, "./members", "")})
    for tag in _unique_nodes(root, [".//tag/entry"]):
        objects["tags"].append({"name": tag.attrib.get("name", "N/A"), "color": get_text(tag, "./color", "None"), "comments": get_text(tag, "./comments", "")})
    for app in _unique_nodes(root, [".//shared/application/entry", ".//vsys/entry/application/entry"]):
        objects["applications"].append({
            "name": app.attrib.get("name", "N/A"),
            "category": get_text(app, "./category", "N/A"),
            "subcategory": get_text(app, "./subcategory", "N/A"),
            "technology": get_text(app, "./technology", "N/A"),
            "risk": get_text(app, "./risk", "N/A"),
        })
    for cert in _unique_nodes(root, [".//shared/certificate/entry", ".//vsys/entry/certificate/entry"]):
        objects["certs"].append({
            "name": cert.attrib.get("name", "N/A"),
            "subject": get_text(cert, "./subject", "N/A"),
            "issuer": get_text(cert, "./issuer", "N/A"),
            "not_before": get_text(cert, "./not-before", "N/A"),
            "not_after": get_text(cert, "./not-after", "N/A"),
        })

    # --- POLICIES ---
    policies: dict[str, list[dict[str, Any]]] = {"security": [], "nat": [], "decryption": [], "pbf": [], "qos": [], "dos": []}
    used_addresses: set[str] = set()
    used_services: set[str] = set()
    used_tags: set[str] = set()

    def append_policy_entries(paths: list[tuple[str, str]], category: str) -> None:
        seen: set[int] = set()
        for xpath, scope in paths:
            for rule in root.findall(xpath):
                marker = id(rule)
                if marker in seen:
                    continue
                seen.add(marker)
                policy = _parse_policy(rule, category, scope)
                policies[category].append(policy)
                if category in {"security", "nat", "decryption", "pbf", "qos", "dos"}:
                    used_addresses.update(_tokens(policy.get("source", "")))
                    used_addresses.update(_tokens(policy.get("destination", "")))
                    used_services.update(_tokens(policy.get("service", "")))
                    used_tags.update(_tokens(policy.get("tags", "")))

    append_policy_entries([
        (".//vsys/entry/rulebase/security/rules/entry", "Local/Vsys"),
        (".//vsys/entry/pre-rulebase/security/rules/entry", "Pre-rulebase"),
        (".//vsys/entry/post-rulebase/security/rules/entry", "Post-rulebase"),
        (".//shared/pre-rulebase/security/rules/entry", "Shared Pre-rulebase"),
        (".//shared/post-rulebase/security/rules/entry", "Shared Post-rulebase"),
        (".//device-group/entry/pre-rulebase/security/rules/entry", "Device Group Pre-rulebase"),
        (".//device-group/entry/post-rulebase/security/rules/entry", "Device Group Post-rulebase"),
    ], "security")

    append_policy_entries([
        (".//vsys/entry/rulebase/nat/rules/entry", "Local/Vsys"),
        (".//vsys/entry/pre-rulebase/nat/rules/entry", "Pre-rulebase"),
        (".//vsys/entry/post-rulebase/nat/rules/entry", "Post-rulebase"),
        (".//shared/pre-rulebase/nat/rules/entry", "Shared Pre-rulebase"),
        (".//shared/post-rulebase/nat/rules/entry", "Shared Post-rulebase"),
        (".//device-group/entry/pre-rulebase/nat/rules/entry", "Device Group Pre-rulebase"),
        (".//device-group/entry/post-rulebase/nat/rules/entry", "Device Group Post-rulebase"),
    ], "nat")

    for category, rule_type in (("decryption", "decryption"), ("pbf", "pbf"), ("qos", "qos"), ("dos", "dos")):
        paths = []
        for base, scope in (
            ("vsys/entry/rulebase", "Local/Vsys"),
            ("vsys/entry/pre-rulebase", "Pre-rulebase"),
            ("vsys/entry/post-rulebase", "Post-rulebase"),
            ("shared/pre-rulebase", "Shared Pre-rulebase"),
            ("shared/post-rulebase", "Shared Post-rulebase"),
            ("device-group/entry/pre-rulebase", "Device Group Pre-rulebase"),
            ("device-group/entry/post-rulebase", "Device Group Post-rulebase"),
        ):
            paths.append((f".//{base}/{rule_type}/rules/entry", scope))
        append_policy_entries(paths, category)

    # Mark unused objects, accounting for references through static groups.
    address_group_members = {g["name"]: set(_tokens(g.get("members", ""))) for g in objects["addr_groups"]}
    service_group_members = {g["name"]: set(_tokens(g.get("members", ""))) for g in objects["svc_groups"]}
    _expand_group_references(used_addresses, address_group_members)
    _expand_group_references(used_services, service_group_members)
    # Dynamic address-group membership is evaluated from tags at runtime. If a
    # policy references one, do not incorrectly label unrelated address objects
    # as unused based only on static XML references.
    referenced_dynamic_group = any(
        group.get("type") == "Dynamic" and group.get("name") in used_addresses
        for group in objects["addr_groups"]
    )
    for obj in objects["addresses"]:
        obj["usage_unknown"] = referenced_dynamic_group and obj["name"] not in used_addresses
        obj["orphaned"] = obj["name"] not in used_addresses and obj["name"] != "any" and not obj["usage_unknown"]
    for obj in objects["services"]:
        obj["orphaned"] = obj["name"] not in used_services and obj["name"] not in {"any", "application-default"}

    # --- SECURITY PROFILES ---
    profiles: dict[str, list[Any]] = {
        "av": [], "spyware": [], "vuln": [], "url": [], "wildfire": [],
        "file_blocking": [], "data_filtering": [], "groups": [], "dos": [],
    }
    profile_paths = {
        "av": ".//profiles/virus/entry",
        "spyware": ".//profiles/spyware/entry",
        "vuln": ".//profiles/vulnerability/entry",
        "url": ".//profiles/url-filtering/entry",
        "wildfire": ".//profiles/wildfire-analysis/entry",
        "file_blocking": ".//profiles/file-blocking/entry",
        "data_filtering": ".//profiles/data-filtering/entry",
        "dos": ".//profiles/dos-protection/entry",
    }
    for key, xpath in profile_paths.items():
        profiles[key] = [node.attrib.get("name", "N/A") for node in _unique_nodes(root, [xpath])]
    for group in _unique_nodes(root, [".//profile-group/entry"]):
        profiles["groups"].append({
            "name": group.attrib.get("name", "N/A"),
            "av": get_members(group, "./virus"),
            "spyware": get_members(group, "./spyware"),
            "vuln": get_members(group, "./vulnerability"),
            "url": get_members(group, "./url-filtering"),
            "wildfire": get_members(group, "./wildfire-analysis"),
            "file_blocking": get_members(group, "./file-blocking"),
            "data_filtering": get_members(group, "./data-filtering"),
        })

    # --- AUTHENTICATION & SERVER PROFILES ---
    auth_profiles = []
    for profile in _unique_nodes(root, [".//authentication-profile/entry"]):
        auth_profiles.append({
            "name": profile.attrib.get("name", "N/A"),
            "method": next((m for m in ("ldap", "radius", "tacplus", "saml-idp", "kerberos", "local-database") if profile.find(f"./method/{m}") is not None), "N/A"),
            "allow_list": get_members(profile, "./allow-list", "any"),
            "user_domain": get_text(profile, "./user-domain", "N/A"),
        })

    server_profiles: list[dict[str, str]] = []
    server_profile_types = ("syslog", "email", "snmp-trap", "http", "ldap", "radius", "tacplus", "netflow", "sftp")
    for profile_type in server_profile_types:
        for profile in _unique_nodes(root, [f".//server-profile/{profile_type}/entry"]):
            server_profiles.append({
                "type": profile_type.upper(),
                "name": profile.attrib.get("name", "N/A"),
                "servers": str(len(profile.findall(".//server/entry")) or len(profile.findall(".//entry"))),
                "description": get_text(profile, "./description", ""),
            })

    # --- LOGGING / LOG FORWARDING ---
    log_settings = []
    for category in ("system", "config", "hip-match", "user-id", "correlation", "globalprotect", "tunnel", "traffic", "threat", "url", "data", "wildfire"):
        for entry in _unique_nodes(root, [f".//log-settings/{category}/entry"]):
            log_settings.append({
                "type": category.upper(),
                "name": entry.attrib.get("name", "N/A"),
                "match_list": get_members(entry, ".//match-list", "N/A"),
            })

    # --- ADDITIONAL DEVICE CONFIGURATION DATA ---
    ssl_profiles = []
    for profile in _unique_nodes(root, [".//ssl-tls-service-profile/entry", ".//ssl-tls-profile/entry"]):
        ssl_profiles.append({
            "name": profile.attrib.get("name", "N/A"),
            "certificate": get_text(profile, "./certificate", "N/A"),
            "protocol_min": get_text(profile, "./protocol-settings/min-version", "N/A"),
            "protocol_max": get_text(profile, "./protocol-settings/max-version", "N/A"),
        })

    # Calculate audit observations (not vendor threat intelligence; static XML checks only).
    findings = _build_findings(policies, objects, zones, vpns)

    return {
        "source_file": path.name,
        "source_path": str(path.resolve()),
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "app_version": APP_VERSION,
        "device_info": device_info,
        "management_services": management_services,
        "admins": admins,
        "interfaces": interfaces,
        "zones": zones,
        "routers": routers,
        "global_protect": global_protect,
        "vpns": vpns,
        "objects": objects,
        "policies": policies,
        "profiles": profiles,
        "auth_profiles": auth_profiles,
        "server_profiles": server_profiles,
        "log_settings": log_settings,
        "ssl_profiles": ssl_profiles,
        "findings": findings,
    }


def _reference_values(element: ET.Element | None, path: str, default: str = "N/A") -> list[str]:
    """Read references stored as either <member> or <entry> in PAN-OS XML."""
    if element is None:
        return []
    parent = element.find(path)
    if parent is None:
        return []
    values = []
    for node in list(parent):
        if node.tag in {"member", "entry"}:
            value = _entry_value(node)
            if value:
                values.append(value)
    if not values and parent.text and parent.text.strip():
        values.append(parent.text.strip())
    return list(dict.fromkeys(values)) or ([default] if default != "N/A" else [])


def _tokens(value: str) -> set[str]:
    if not value or value in {"any", "N/A"}:
        return set()
    return {item.strip() for item in value.split(",") if item.strip() and item.strip() not in {"any", "N/A"}}


def _expand_group_references(used: set[str], group_map: dict[str, set[str]]) -> None:
    pending = list(used)
    visited: set[str] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        for member in group_map.get(current, set()):
            if member not in used:
                used.add(member)
                pending.append(member)


def _parse_policy(rule: ET.Element, category: str, scope: str) -> dict[str, Any]:
    src = get_members(rule, "./source")
    dst = get_members(rule, "./destination")
    service = get_members(rule, "./service")
    tags = get_members(rule, "./tag")
    action = get_text(rule, "./action", "N/A")
    if action == "N/A":
        action_node = rule.find("./action")
        if action_node is not None and len(action_node):
            action = ", ".join(child.tag for child in list(action_node))
    disabled = get_text(rule, "./disabled", "no").lower()

    profile_group = get_members(rule, "./profile-setting/group", "None")
    custom_profiles = {}
    for key, path in (
        ("Antivirus", "virus"), ("Anti-Spyware", "spyware"), ("Vulnerability", "vulnerability"),
        ("URL Filtering", "url-filtering"), ("WildFire", "wildfire-analysis"),
        ("File Blocking", "file-blocking"), ("Data Filtering", "data-filtering"),
    ):
        value = get_members(rule, f"./profile-setting/profiles/{path}", "")
        if value:
            custom_profiles[key] = value
    if profile_group == "None" and custom_profiles:
        profile_group = "Custom Profiles"

    log_start = get_text(rule, "./log-start", "no").lower()
    log_end = get_text(rule, "./log-end", "no").lower()
    log_forward = get_text(rule, "./log-setting", "None")
    from_zone = get_members(rule, "./from")
    to_zone = get_members(rule, "./to")
    is_any_any = src == "any" and dst == "any" and from_zone == "any" and to_zone == "any"
    is_risky = category == "security" and action == "allow" and disabled != "yes" and is_any_any and profile_group == "None" and log_end != "yes"

    parsed = {
        "name": rule.attrib.get("name", "N/A"),
        "uuid": rule.attrib.get("uuid", "N/A"),
        "scope": scope,
        "desc": get_text(rule, "./description", ""),
        "tags": tags,
        "users": get_members(rule, "./source-user"),
        "from": from_zone,
        "to": to_zone,
        "source": src,
        "destination": dst,
        "app": get_members(rule, "./application"),
        "service": service,
        "svc": service,
        "action": action,
        "disabled": disabled,
        "log_start": log_start,
        "log_end": log_end,
        "log_fwd": log_forward,
        "prof_group": profile_group,
        "custom_profiles": custom_profiles,
        "risky": is_risky,
        "schedule": get_text(rule, "./schedule", "N/A"),
        "negate_source": get_text(rule, "./negate-source", "no"),
        "negate_destination": get_text(rule, "./negate-destination", "no"),
        "hip_profiles": get_members(rule, "./source-hip"),
        "target": get_members(rule, "./target/devices"),
    }
    if category == "nat":
        parsed.update({
            "source_translation": _describe_translation(rule, "./source-translation"),
            "destination_translation": _describe_translation(rule, "./destination-translation"),
            "service_translation": get_text(rule, "./service", "N/A"),
            "bi_directional": get_text(rule, "./bi-directional", "no"),
        })
    elif category == "pbf":
        parsed.update({
            "action": "Forward" if rule.find("./action/forward") is not None else action,
            "egress": get_text(rule, "./action/forward/egress-interface", "N/A"),
            "nexthop": get_text(rule, "./action/forward/nexthop/ip-address", get_text(rule, "./action/forward/nexthop/fqdn", "N/A")),
            "monitor": get_text(rule, "./monitor/enable", "no"),
        })
    elif category == "decryption":
        parsed.update({
            "decrypt_type": next((k for k in ("ssl-forward-proxy", "ssl-inbound-inspection", "ssh-proxy", "no-decrypt") if rule.find(f"./{k}") is not None), "N/A"),
            "profile": get_text(rule, "./options/ssl-protocol-settings", "N/A"),
        })
    elif category in {"qos", "dos"}:
        parsed.update({"zone": from_zone, "protection": get_text(rule, "./action", "N/A")})
    return parsed


def _describe_translation(rule: ET.Element, path: str) -> str:
    """Summarize NAT translation without exposing unrelated leaf values."""
    node = rule.find(path)
    if node is None:
        return "None"

    def describe(current: ET.Element) -> str:
        children = list(current)
        if not children:
            value = _clean(current.text, "")
            return value or current.attrib.get("name", "") or current.tag
        parts = []
        for child in children:
            nested = describe(child)
            if nested:
                # Avoid repeating wrapper names for member/entry containers.
                if child.tag in {"member", "entry"}:
                    parts.append(nested)
                else:
                    parts.append(f"{child.tag}: {nested}")
        return "; ".join(parts)

    return describe(node) or "Configured"


def _build_findings(policies: dict[str, list[dict[str, Any]]], objects: dict[str, list[dict[str, Any]]],
                    zones: list[dict[str, str]], vpns: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for rule in policies["security"]:
        if rule["disabled"] == "yes" or rule["action"] != "allow":
            continue
        if rule["risky"]:
            findings.append({"severity": "High", "type": "Security policy", "object": rule["name"],
                             "details": "Active Any-Any allow rule without a Security profile and without session-end logging."})
        elif rule["prof_group"] == "None":
            findings.append({"severity": "Medium", "type": "Security policy", "object": rule["name"],
                             "details": "The allow rule has no Security profile group or individual Security profiles assigned."})
        if rule["log_end"] != "yes":
            findings.append({"severity": "Low", "type": "Logging", "object": rule["name"],
                             "details": "Session-end logging is disabled (log-end != yes)."})
        if rule["desc"] == "":
            findings.append({"severity": "Info", "type": "Documentation", "object": rule["name"],
                             "details": "The rule has no description."})

    for obj in objects["addresses"]:
        if obj.get("orphaned"):
            findings.append({"severity": "Info", "type": "Unused object", "object": obj["name"],
                             "details": "The address object was not found in the references of the analyzed policies."})
    for obj in objects["services"]:
        if obj.get("orphaned"):
            findings.append({"severity": "Info", "type": "Unused object", "object": obj["name"],
                             "details": "The service object was not found in the references of the analyzed policies."})
    for zone in zones:
        if zone["interfaces"] == "N/A":
            findings.append({"severity": "Low", "type": "Network", "object": zone["name"],
                             "details": "The zone has no interface assigned in the analyzed export."})

    ike_names = {g["name"] for g in vpns["ike"]}
    for tunnel in vpns["ipsec"]:
        bound = _tokens(tunnel.get("ike_gateway", ""))
        if bound and not (bound & ike_names):
            findings.append({"severity": "Medium", "type": "VPN", "object": tunnel["name"],
                             "details": "The IPSec tunnel references an IKE Gateway that was not found in the analyzed configuration."})
    for profile in vpns["crypto_ike"] + vpns["crypto_ipsec"]:
        algorithms = " ".join(str(profile.get(k, "")) for k in ("hash", "auth", "enc", "dh")).lower()
        weak_tokens = {"3des", "des", "md5", "sha1", "group1", "group2", "group5"}
        present_tokens = set(re.findall(r"[a-z0-9-]+", algorithms))
        weak = sorted(weak_tokens & present_tokens)
        if weak:
            findings.append({"severity": "Medium", "type": "Cryptography", "object": profile["name"],
                             "details": "The profile contains an algorithm/group that requires review: " + ", ".join(weak) + "."})
    return findings


# ------------------------------ HTML RENDERING ------------------------------

def _pill(value: Any, kind: str = "neutral") -> str:
    return f'<span class="pill {esc(kind)}">{esc(value)}</span>'


def _cell(value: Any, mono: bool = False) -> str:
    cls = ' class="mono"' if mono else ""
    return f"<span{cls}>{esc(value) if value not in (None, '') else '—'}</span>"


def _table(title: str, headers: list[str], rows: list[Any], table_id: str = "", note: str = "",
           empty: str = "No data in the analyzed XML export.") -> str:
    if rows:
        body = []
        for item in rows:
            if isinstance(item, dict):
                cells = item.get("cells", [])
                row_class = item.get("class", "")
                risk = item.get("risk", "false")
            else:
                cells, row_class, risk = item, "", "false"
            tds = "".join(f"<td>{value}</td>" for value in cells)
            body.append(f'<tr class="{esc(row_class)}" data-risk="{esc(risk)}">{tds}</tr>')
        body_html = "".join(body)
    else:
        body_html = f'<tr><td class="empty-cell" colspan="{max(1, len(headers))}">{esc(empty)}</td></tr>'
    head = "".join(f"<th scope=\"col\">{esc(label)}<span class=\"sort-mark\"></span></th>" for label in headers)
    hint = f'<div class="panel-note">{esc(note)}</div>' if note else ""
    count = len(rows)
    return f'''<section class="panel">
      <div class="panel-heading"><div class="panel-title">{esc(title)}</div><div class="panel-tools"><span class="row-count">{count}</span><button class="icon-button" type="button" title="Refresh panel" aria-label="Refresh panel" onclick="refreshPanel(this)">↻</button><button class="icon-button" type="button" title="Collapse panel" aria-label="Collapse panel" onclick="togglePanel(this)">−</button></div></div>
      {hint}<div class="table-wrap"><table class="data-table" data-table-id="{esc(table_id or re.sub(r'[^a-z0-9]+','-',title.lower()).strip('-'))}"><thead><tr>{head}</tr></thead><tbody>{body_html}</tbody></table></div>
    </section>'''


def _panel(title: str, body: str, note: str = "", count: str = "") -> str:
    hint = f'<div class="panel-note">{esc(note)}</div>' if note else ""
    count_html = f'<span class="row-count">{esc(count)}</span>' if count else ""
    return f'''<section class="panel"><div class="panel-heading"><div class="panel-title">{esc(title)}</div><div class="panel-tools">{count_html}<button class="icon-button" type="button" title="Collapse panel" aria-label="Collapse panel" onclick="togglePanel(this)">−</button></div></div>{hint}<div class="panel-body">{body}</div></section>'''


def _kv(items: list[tuple[str, Any]]) -> str:
    return '<dl class="kv-grid">' + "".join(
        f'<div class="kv-item"><dt>{esc(label)}</dt><dd>{esc(value) if value not in (None, "") else "—"}</dd></div>'
        for label, value in items
    ) + "</dl>"


def _stat(label: str, value: Any, sub: str, tone: str = "") -> str:
    return f'<div class="stat-card {esc(tone)}"><div class="stat-label">{esc(label)}</div><div class="stat-value">{esc(value)}</div><div class="stat-sub">{esc(sub)}</div></div>'


def _policy_rows(rules: list[dict[str, Any]], category: str = "security") -> list[dict[str, Any]]:
    result = []
    for rule in rules:
        row_class = ""
        if rule.get("disabled") == "yes":
            row_class += " disabled-row"
        if rule.get("risky"):
            row_class += " risky-row"
        if category == "security":
            action_kind = "good" if rule.get("action") == "allow" else "bad" if rule.get("action") in {"deny", "drop", "reset-client", "reset-server", "reset-both"} else "neutral"
            cells = [
                f'<strong>{esc(rule.get("name"))}</strong><span class="subline">{esc(rule.get("scope"))} · {esc(rule.get("desc") or "brak opisu")}</span>',
                _cell(rule.get("from")), _cell(rule.get("source"), True), _cell(rule.get("to")), _cell(rule.get("destination"), True),
                _cell(rule.get("app")), _cell(rule.get("service")),
                _pill(rule.get("action", "N/A"), action_kind) + f'<span class="subline">Profile: {esc(rule.get("prof_group"))}</span>'
                + f'<span class="subline">Log start/end: {esc(rule.get("log_start"))}/{esc(rule.get("log_end"))}</span>'
                + f'<span class="subline">Log forwarding: {esc(rule.get("log_fwd"))}</span>',
                _pill("DISABLED", "muted") if rule.get("disabled") == "yes" else (_pill("POTENTIAL RISK", "bad") if rule.get("risky") else _pill("Active", "good")),
            ]
        elif category == "nat":
            cells = [f'<strong>{esc(rule.get("name"))}</strong><span class="subline">{esc(rule.get("scope"))}</span>', _cell(rule.get("from")), _cell(rule.get("to")),
                     _cell(rule.get("source"), True), _cell(rule.get("destination"), True), _cell(rule.get("source_translation")), _cell(rule.get("destination_translation")),
                     _pill("DISABLED", "muted") if rule.get("disabled") == "yes" else _pill("Active", "good")]
        elif category == "pbf":
            cells = [f'<strong>{esc(rule.get("name"))}</strong><span class="subline">{esc(rule.get("scope"))}</span>', _cell(rule.get("from")), _cell(rule.get("source"), True),
                     _cell(rule.get("destination"), True), _cell(rule.get("egress")), _cell(rule.get("nexthop")), _cell(rule.get("monitor"))]
        else:
            cells = [f'<strong>{esc(rule.get("name"))}</strong><span class="subline">{esc(rule.get("scope"))}</span>', _cell(rule.get("from")), _cell(rule.get("to")),
                     _cell(rule.get("source"), True), _cell(rule.get("destination"), True), _cell(rule.get("action")), _cell(rule.get("schedule"))]
        result.append({"cells": cells, "class": row_class, "risk": "true" if rule.get("risky") else "false"})
    return result


def _render_page(page_id: str, title: str, content: str, active: bool = False) -> str:
    return f'<section class="page {"active" if active else ""}" id="page-{esc(page_id)}" data-page="{esc(page_id)}"><div class="page-heading"><div><div class="eyebrow">PA-VM CONFIGURATION VIEW</div><h1>{esc(title)}</h1></div><div class="page-meta">Source: {esc(page_id.upper())}</div></div>{content}</section>'


def _build_pages(data: dict[str, Any]) -> tuple[str, str]:
    di = data["device_info"]
    policies = data["policies"]
    objects = data["objects"]
    vpns = data["vpns"]
    findings = data["findings"]

    security = policies["security"]
    active_security = [p for p in security if p.get("disabled") != "yes"]
    allow_count = sum(1 for p in active_security if p.get("action") == "allow")
    deny_count = sum(1 for p in active_security if p.get("action") != "allow")
    high_findings = sum(1 for f in findings if f["severity"] == "High")
    medium_findings = sum(1 for f in findings if f["severity"] == "Medium")
    orphan_addresses = sum(1 for a in objects["addresses"] if a.get("orphaned"))
    orphan_services = sum(1 for a in objects["services"] if a.get("orphaned"))

    # DASHBOARD
    stats = "<div class=\"stat-grid\">" + "".join([
        _stat("Security rules", len(security), f"{len(active_security)} active"),
        _stat("Allow rules", allow_count, "Active allow rules", "green"),
        _stat("Deny / other", deny_count, "Active deny / other rules", "blue"),
        _stat("Audit findings", len(findings), f"{high_findings} high · {medium_findings} medium", "orange" if high_findings or medium_findings else "green"),
        _stat("Interfaces", len(data["interfaces"]), "Interface entries in XML", "blue"),
        _stat("Address objects", len(objects["addresses"]), f"{orphan_addresses} unused according to analysis", "orange" if orphan_addresses else ""),
    ]) + "</div>"
    general_items = [
        ("Device Name", di["hostname"]), ("Management IP Address", di["ip_address"]),
        ("Management Netmask", di["netmask"]), ("Management Default Gateway", di["default_gateway"]),
        ("DNS Primary", di["dns_primary"]), ("DNS Secondary", di["dns_secondary"]),
        ("Panorama Server", di["panorama_server"]), ("Domain", di["domain"]),
        ("Time Zone", di["timezone"]), ("Locale", di["locale"]),
        ("High Availability", di["ha_enabled"]), ("HA1 Peer IP", di["ha_peer_ip"]),
    ]
    admin_rows = [[f'<strong>{esc(a["name"])}</strong>', _cell(a["role"]), _cell(a["password_profile"]), _cell(a["phash_present"])] for a in data["admins"]]
    finding_rows = []
    for item in findings:
        severity_class = {"High": "bad", "Medium": "warn", "Low": "neutral", "Info": "muted"}.get(item["severity"], "neutral")
        finding_rows.append({"cells": [_pill(item["severity"], severity_class), _cell(item["type"]), f'<strong>{esc(item["object"])}</strong>', _cell(item["details"])],
                             "risk": "true" if item["severity"] in {"High", "Medium"} else "false"})
    dashboard = stats
    dashboard += '<div class="dashboard-grid dashboard-grid-main">'
    dashboard += _panel("General Information", _kv(general_items), note="Values read from the XML configuration export.")
    dashboard += _panel("Configured Administrators", _table("", ["Admin", "Role / Permissions", "Password Profile", "Password Hash"], admin_rows, "admins"),
                        note="Lista skonfigurowanych kont. Nie jest to lista active sesji logowania.")
    dashboard += '</div><div class="dashboard-grid">'
    dashboard += _panel("Configuration Runtime Widgets", '<div class="runtime-grid">'
                        '<div class="runtime-item"><span class="runtime-label">Logged In Admins</span><strong>Unavailable</strong><small>Active sessions are not stored in running-config.xml.</small></div>'
                        '<div class="runtime-item"><span class="runtime-label">System Logs</span><strong>Unavailable</strong><small>Logs require runtime data / API / log exports.</small></div>'
                        '<div class="runtime-item"><span class="runtime-label">Config Logs</span><strong>Unavailable</strong><small>Change history requires log exports or API access.</small></div>'
                        '<div class="runtime-item"><span class="runtime-label">Data Logs / ACC</span><strong>Unavailable</strong><small>Traffic and ACC statistics are not available from the XML configuration.</small></div>'
                        '</div>', note="Operational data is intentionally not fabricated.")
    dashboard += _panel("Policy Distribution", f'<div class="chart-block"><div class="donut" style="--allow:{allow_count};--deny:{deny_count};--total:{max(allow_count+deny_count,1)}"><div class="donut-center"><strong>{allow_count+deny_count}</strong><span>ACTIVE</span></div></div><div class="legend"><span><i class="dot allow"></i>Allow <b>{allow_count}</b></span><span><i class="dot deny"></i>Deny / other <b>{deny_count}</b></span><span><i class="dot disabled-dot"></i>Disabled <b>{len(security)-len(active_security)}</b></span></div></div>')
    dashboard += '</div>' + _table("Audit Findings", ["Severity", "Category", "Object", "Observation"], finding_rows, "findings",
                                            note="These results are static items for review, not a complete PAN-OS security audit.")

    # NETWORK
    zone_rows = [[f'<strong>{esc(z["name"])}</strong>', _cell(z["type"]), _cell(z["interfaces"], True), _cell(z["enable_user_id"])] for z in data["zones"]]
    intf_rows = []
    for i in data["interfaces"]:
        intf_rows.append([f'<strong>{esc(i["name"])}</strong><span class="subline">{esc(i["comment"])}</span>', _cell(i["type"]), _pill(i["mode"], "neutral"), _cell(i["ip"], True), _cell(i["vlan"]), _cell(i["mgmt"]), _cell(i["mtu"]), _cell(i["link_state"])])
    router_rows = []
    for r in data["routers"]:
        route_text = "<br>".join(f'<span class="route-line"><b>{esc(rt["name"])}</b> · {esc(rt["destination"])} → {esc(rt["nexthop"])}</span>' for rt in r["routes"]) or "—"
        router_rows.append([f'<strong>{esc(r["name"])}</strong>', _cell(r["interfaces"], True), _cell(r["protocols"]), _cell(r["bgp_peer_groups"]), _cell(r["ospf_areas"]), route_text])
    gp_rows = []
    for p in data["global_protect"]["portals"]:
        gp_rows.append([f'<strong>{esc(p["name"])}</strong>', _pill("Portal", "blue"), _cell(p["interface"]), _cell(p["address"], True), _cell(p["auth_profile"])])
    for g in data["global_protect"]["gateways"]:
        gp_rows.append([f'<strong>{esc(g["name"])}</strong>', _pill("Gateway", "good"), _cell(g["interface"]), _cell(g["address"], True), _cell(g["ip_pool"], True)])
    network = _table("Zones", ["Zone Name", "Type", "Assigned Interfaces", "User-ID"], zone_rows, "zones")
    network += _table("Interfaces & Subinterfaces", ["Interface", "Type", "Mode", "IP Address", "VLAN Tag", "Mgmt Profile", "MTU", "Link State"], intf_rows, "interfaces")
    network += _table("Virtual Routers", ["Router", "Interfaces", "Dynamic Protocols", "BGP Peer Groups", "OSPF Areas", "Static Routes"], router_rows, "routers")
    network += _table("GlobalProtect Portals & Gateways", ["Name", "Type", "Interface", "Local Address", "Auth Profile / IP Pool"], gp_rows, "global-protect")

    # VPN
    ike_rows = [[f'<strong>{esc(v["name"])}</strong>', _cell(v["version"]), _cell(v["interface"]), _cell(v["local_ip"], True), _cell(v["peer_ip"], True), _cell(v["profile"]), _cell(v["passive"])] for v in vpns["ike"]]
    ipsec_rows = [[f'<strong>{esc(v["name"])}</strong>', _cell(v["interface"]), _cell(v["ike_gateway"]), _cell(v["profile"]), _cell(v["proxy_ids"]), _cell(v["monitor"])] for v in vpns["ipsec"]]
    crypto_rows = []
    for p in vpns["crypto_ike"]:
        crypto_rows.append([f'<strong>{esc(p["name"])}</strong>', _pill("IKE", "blue"), _cell(p["enc"]), _cell(p["hash"]), _cell(p["dh"]), _cell(p["lifetime"])])
    for p in vpns["crypto_ipsec"]:
        crypto_rows.append([f'<strong>{esc(p["name"])}</strong>', _pill("IPSec", "neutral"), _cell(p["enc"]), _cell(p["auth"]), _cell(p["dh"]), _cell(p["lifetime"])])
    vpn = _table("IKE Gateways · Phase 1", ["Gateway", "Version", "Local Interface", "Local IP", "Peer IP / FQDN", "IKE Crypto Profile", "Passive"], ike_rows, "ike")
    vpn += _table("IPSec Tunnels · Phase 2", ["Tunnel", "Tunnel Interface", "IKE Gateway", "IPSec Crypto Profile", "Proxy IDs", "Monitor"], ipsec_rows, "ipsec")
    vpn += _table("Crypto Profiles", ["Profile", "Type", "Encryption", "Hash / Authentication", "DH Group", "Lifetime (h)"], crypto_rows, "crypto")

    # OBJECTS
    address_rows = [[f'<strong>{esc(a["name"])}</strong><span class="subline">{esc(a["desc"])}</span>', _pill(a["type"], "neutral"), _cell(a["value"], True), _cell(a["tag"]), _pill("UNUSED", "warn") if a.get("orphaned") else (_pill("Usage unknown", "muted") if a.get("usage_unknown") else _pill("Referenced", "good"))] for a in objects["addresses"]]
    addr_group_rows = [[f'<strong>{esc(g["name"])}</strong>', _pill(g["type"], "neutral"), _cell(g["members"]), _cell(g["dynamic"])] for g in objects["addr_groups"]]
    service_rows = [[f'<strong>{esc(s["name"])}</strong><span class="subline">{esc(s["description"])}</span>', _pill(s["protocol"], "blue"), _cell(s["port"], True), _cell(s["source_port"], True), _pill("UNUSED", "warn") if s.get("orphaned") else _pill("Referenced", "good")] for s in objects["services"]]
    service_group_rows = [[f'<strong>{esc(g["name"])}</strong>', _cell(g["members"])] for g in objects["svc_groups"]]
    tag_rows = [[f'<strong>{esc(t["name"])}</strong>', _cell(t["color"]), _cell(t["comments"])] for t in objects["tags"]]
    cert_rows = [[f'<strong>{esc(c["name"])}</strong>', _cell(c["subject"]), _cell(c["issuer"]), _cell(c["not_before"]), _cell(c["not_after"])] for c in objects["certs"]]
    object_page = _table("Address Objects", ["Name / Description", "Type", "Value", "Tags", "Usage"], address_rows, "addresses")
    object_page += _table("Address Groups", ["Name", "Group Type", "Static Members", "Dynamic Filter"], addr_group_rows, "address-groups")
    object_page += _table("Service Objects", ["Name / Description", "Protocol", "Destination Port", "Source Port", "Usage"], service_rows, "services")
    object_page += _table("Service Groups", ["Name", "Members"], service_group_rows, "service-groups")
    app_rows = [[f'<strong>{esc(a["name"])}</strong>', _cell(a["category"]), _cell(a["subcategory"]), _cell(a["technology"]), _cell(a["risk"])] for a in objects["applications"]]
    object_page += _table("Custom Applications", ["Application", "Category", "Subcategory", "Technology", "Risk"], app_rows, "applications")
    object_page += _table("Tags", ["Name", "Color", "Comments"], tag_rows, "tags")
    object_page += _table("Certificates", ["Certificate", "Subject", "Issuer", "Not Before", "Not After"], cert_rows, "certificates")

    # POLICIES
    security_rows = _policy_rows(security, "security")
    nat_rows = _policy_rows(policies["nat"], "nat")
    decrypt_rows = _policy_rows(policies["decryption"], "other")
    pbf_rows = _policy_rows(policies["pbf"], "pbf")
    qos_rows = _policy_rows(policies["qos"], "other")
    dos_rows = _policy_rows(policies["dos"], "other")
    policy_page = _table("Security Policy Rules", ["Rule / Scope", "From Zone", "Source", "To Zone", "Destination", "Application", "Service", "Action / Profiles / Logging", "Status"], security_rows, "security-rules",
                         note="Red rows indicate potentially risky Any-Any allow rules without a profile and session-end logging. Click a table header to sort.")
    policy_page += _table("NAT Policies", ["Rule / Scope", "From", "To", "Source", "Destination", "Source Translation", "Destination Translation", "Status"], nat_rows, "nat-rules")
    policy_page += _table("Decryption Policies", ["Rule / Scope", "From", "To", "Source", "Destination", "Action", "Schedule"], decrypt_rows, "decryption-rules")
    policy_page += _table("Policy Based Forwarding", ["Rule / Scope", "From", "Source", "Destination", "Egress Interface", "Next Hop", "Monitor"], pbf_rows, "pbf-rules")
    policy_page += _table("QoS Policies", ["Rule / Scope", "From", "To", "Source", "Destination", "Action", "Schedule"], qos_rows, "qos-rules")
    policy_page += _table("DoS Protection Policies", ["Rule / Scope", "From", "To", "Source", "Destination", "Action", "Schedule"], dos_rows, "dos-rules")

    # PROFILES
    profile_group_rows = [[f'<strong>{esc(pg["name"])}</strong>', _cell(pg["av"]), _cell(pg["spyware"]), _cell(pg["vuln"]), _cell(pg["url"]), _cell(pg["wildfire"]), _cell(pg["file_blocking"]), _cell(pg["data_filtering"])] for pg in data["profiles"]["groups"]]
    profile_rows = []
    for key, label in (("av", "Antivirus"), ("spyware", "Anti-Spyware"), ("vuln", "Vulnerability"), ("url", "URL Filtering"), ("wildfire", "WildFire Analysis"), ("file_blocking", "File Blocking"), ("data_filtering", "Data Filtering"), ("dos", "DoS Protection")):
        for name in data["profiles"][key]:
            profile_rows.append([_cell(label), f'<strong>{esc(name)}</strong>'])
    profile_page = _table("Security Profile Groups", ["Group Name", "Antivirus", "Anti-Spyware", "Vulnerability", "URL Filtering", "WildFire", "File Blocking", "Data Filtering"], profile_group_rows, "profile-groups")
    profile_page += _table("Individual Security Profiles", ["Profile Type", "Profile Name"], profile_rows, "security-profiles")

    # DEVICE / AUTH / LOGGING
    auth_rows = [[f'<strong>{esc(a["name"])}</strong>', _pill(a["method"], "blue"), _cell(a["allow_list"]), _cell(a["user_domain"])] for a in data["auth_profiles"]]
    server_rows = [[_pill(s["type"], "neutral"), f'<strong>{esc(s["name"])}</strong>', _cell(s["servers"]), _cell(s["description"])] for s in data["server_profiles"]]
    log_rows = [[_pill(l["type"], "blue"), f'<strong>{esc(l["name"])}</strong>', _cell(l["match_list"])] for l in data["log_settings"]]
    ssl_rows = [[f'<strong>{esc(p["name"])}</strong>', _cell(p["certificate"]), _cell(p["protocol_min"]), _cell(p["protocol_max"])] for p in data["ssl_profiles"]]
    device = _panel("General Settings", _kv([
        ("Hostname", di["hostname"]), ("Domain", di["domain"]), ("Timezone", di["timezone"]), ("Locale", di["locale"]),
        ("Login Banner", di["login_banner"]), ("SSL/TLS Service Profile", di["ssl_tls_profile"]),
        ("Panorama Server", di["panorama_server"]), ("HA Enabled", di["ha_enabled"]), ("HA1 IP", di["ha1_ip"]), ("HA1 Peer IP", di["ha_peer_ip"]),
        ("Telemetry Setting", di["telemetry"]), ("Permitted Management IPs", _join(di["permitted_ip"])),
    ]))
    device += _table("Management Services", ["Service", "Configured Value"], [[_cell(s["service"]), _cell(s["value"])] for s in data["management_services"]], "management-services")
    device += _table("Authentication Profiles", ["Profile", "Method", "Allow List", "User Domain"], auth_rows, "auth-profiles")
    device += _table("Server Profiles", ["Type", "Profile Name", "Server Entries", "Description"], server_rows, "server-profiles")
    device += _table("Log Settings / Forwarding", ["Category", "Profile", "Match List"], log_rows, "log-settings")
    device += _table("SSL/TLS Service Profiles", ["Profile", "Certificate", "Minimum Protocol", "Maximum Protocol"], ssl_rows, "ssl-profiles")

    # MONITOR: explicit offline/runtime boundary + static log configuration.
    monitor = '<div class="notice notice-info"><strong>Offline mode — XML configuration export</strong><p>This report analyzes configuration stored in a file. It does not connect to the firewall or retrieve current sessions, traffic counters, ACC, system logs, data logs, or service status. Access to this data would require PAN-OS XML API integration or separate log exports.</p></div>'
    monitor += '<div class="dashboard-grid">'
    monitor += _panel("Runtime Widgets", '<div class="runtime-grid">'
                      '<div class="runtime-item"><span class="runtime-label">Logged In Admins</span><strong>Not in XML</strong><small>Current session information is unavailable.</small></div>'
                      '<div class="runtime-item"><span class="runtime-label">System Logs</span><strong>Not in XML</strong><small>Device log data is unavailable.</small></div>'
                      '<div class="runtime-item"><span class="runtime-label">Config Logs</span><strong>Not in XML</strong><small>Commit and change history is unavailable.</small></div>'
                      '<div class="runtime-item"><span class="runtime-label">ACC Risk Factor</span><strong>Not in XML</strong><small>Telemetry and statistics for the last 60 minutes are unavailable.</small></div>'
                      '</div>')
    monitor += _panel("Configuration Snapshot", _kv([
        ("Input file", data["source_file"]), ("Hostname", di["hostname"]), ("Management IP", di["ip_address"]),
        ("Configured administrators", len(data["admins"])), ("Security rules", len(security)),
        ("Log forwarding profiles", len(data["log_settings"])), ("Generated at", data["generated_at"]),
    ]))
    monitor += '</div>' + _table("Configured Log Profiles", ["Category", "Profile", "Match List"], log_rows, "monitor-log-profiles")

    nav = [
        ("dashboard", "Dashboard", "◫", "MAIN"), ("monitor", "Monitor", "◷", "MAIN"),
        ("policies", "Policies", "▤", "CONFIGURATION"), ("objects", "Objects", "◇", "CONFIGURATION"),
        ("network", "Network", "⌁", "CONFIGURATION"), ("vpn", "IPSec VPN", "↔", "CONFIGURATION"),
        ("profiles", "Security Profiles", "⛨", "SECURITY"), ("device", "Device / Setup", "⚙", "SYSTEM"),
    ]
    pages = "".join([
        _render_page("dashboard", "Dashboard", dashboard, True),
        _render_page("monitor", "Monitor", monitor),
        _render_page("policies", "Policies", policy_page),
        _render_page("objects", "Objects", object_page),
        _render_page("network", "Network", network),
        _render_page("vpn", "IPSec VPN & Crypto", vpn),
        _render_page("profiles", "Security Profiles", profile_page),
        _render_page("device", "Device / Setup", device),
    ])
    nav_html = ""
    last_group = None
    for page_id, label, icon, group in nav:
        if group != last_group:
            nav_html += f'<div class="nav-group-label">{esc(group)}</div>'
            last_group = group
        nav_html += f'<button class="side-link {"active" if page_id == "dashboard" else ""}" data-target="{esc(page_id)}" type="button"><span class="nav-icon">{esc(icon)}</span><span>{esc(label)}</span><span class="nav-count">{_nav_count(page_id, data)}</span></button>'
    return nav_html, pages


def _nav_count(page_id: str, data: dict[str, Any]) -> str:
    counts = {
        "dashboard": "",
        "monitor": "",
        "policies": str(sum(len(v) for v in data["policies"].values())),
        "objects": str(sum(len(data["objects"][k]) for k in ("addresses", "addr_groups", "services", "svc_groups"))),
        "network": str(len(data["interfaces"]) + len(data["zones"])),
        "vpn": str(len(data["vpns"]["ike"]) + len(data["vpns"]["ipsec"])),
        "profiles": str(len(data["profiles"]["groups"])),
        "device": str(len(data["admins"])),
    }
    return f'<small>{esc(counts.get(page_id, ""))}</small>' if counts.get(page_id) else ""


def generate_html(output_path: str | os.PathLike[str], data: dict[str, Any]) -> None:
    nav_html, pages_html = _build_pages(data)
    safe_json = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    try:
        original_xml = Path(data["source_path"]).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError):
        original_xml = ""
    safe_xml = json.dumps(original_xml, ensure_ascii=False).replace("</", "<\\/")
    title = f"PA-View · {data['device_info'].get('hostname', 'Palo Alto')}"
    template = r'''<!DOCTYPE html>
<html lang="pl">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="Read-only Palo Alto Networks PAN-OS configuration dashboard generated from XML">
<title>__TITLE__</title>
<style>
:root{--nav:#202833;--nav2:#17212b;--yellow:#f5b900;--yellow2:#e8aa00;--bg:#eef0f2;--panel:#fff;--line:#d5d9dd;--head:#d9dcdf;--text:#26313b;--muted:#77818a;--blue:#1689c9;--green:#16834c;--red:#c43e35;--orange:#c47b14;--shadow:0 1px 2px rgba(18,28,38,.08);--sidebar:226px}
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Arial,Helvetica,sans-serif;color:var(--text);background:var(--bg);font-size:13px}
button,input,select{font:inherit}.topbar{height:58px;background:var(--nav);color:#e9edf0;display:flex;align-items:center;padding:0 18px;gap:24px;border-bottom:4px solid var(--yellow);position:sticky;top:0;z-index:20;box-shadow:0 2px 7px #0002}
.brand{display:flex;align-items:center;gap:9px;font-size:20px;font-weight:700;white-space:nowrap;min-width:185px}.brand-mark{width:22px;height:22px;display:inline-grid;place-items:center;background:var(--yellow);color:#1d2731;font-weight:900;clip-path:polygon(25% 0,100% 0,75% 50%,100% 100%,25% 100%,0 50%)}.topnav{display:flex;align-self:stretch;align-items:stretch;gap:2px;overflow:auto}.topnav button{border:0;background:transparent;color:#aeb6bf;padding:0 15px;cursor:pointer;font-weight:600;white-space:nowrap;border-bottom:3px solid transparent}.topnav button:hover,.topnav button.active{color:var(--yellow);background:#ffffff08;border-bottom-color:var(--yellow)}.topbar-right{margin-left:auto;display:flex;align-items:center;gap:12px;color:#abb4bd;white-space:nowrap}.readonly{border:1px solid #57616c;border-radius:3px;padding:6px 9px;font-size:11px;color:#d1d7dc}
.layout{display:grid;grid-template-columns:var(--sidebar) minmax(0,1fr);min-height:calc(100vh - 58px)}.sidebar{background:#e7e9eb;border-right:1px solid #c8cdd1;padding:14px 9px 24px;position:sticky;top:58px;height:calc(100vh - 58px);overflow:auto}.sidebar-caption{font-size:10px;letter-spacing:.1em;color:#929aa1;padding:4px 10px 12px}.nav-group-label{font-size:10px;letter-spacing:.08em;color:#8a9299;padding:16px 10px 6px;font-weight:700}.side-link{width:100%;display:flex;align-items:center;gap:10px;border:0;border-left:3px solid transparent;text-align:left;background:transparent;color:#4c5863;padding:9px 10px;cursor:pointer;border-radius:2px;margin:1px 0}.side-link:hover{background:#dce1e5}.side-link.active{background:#fff;border-left-color:var(--yellow2);color:#1e2b36;font-weight:700;box-shadow:var(--shadow)}.nav-icon{width:18px;text-align:center;font-size:16px;color:#6b8799}.side-link.active .nav-icon{color:#bd8c00}.nav-count{margin-left:auto;color:#9ba2a8;font-size:11px}
.main{min-width:0;padding:0 14px 22px}.toolbar{height:42px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #d6dade;margin:0 -14px 14px;padding:0 14px;background:#f7f8f9;position:sticky;top:58px;z-index:10}.toolbar-label{color:#747e87;font-size:12px}.search-wrap{margin-left:auto;display:flex;align-items:center;gap:7px}.search-wrap input{width:min(320px,27vw);height:29px;padding:5px 10px;border:1px solid #c8cfd5;border-radius:3px;background:white;outline:none}.search-wrap input:focus{border-color:var(--blue);box-shadow:0 0 0 2px #1689c91b}.tool-btn{border:1px solid #bec6cc;background:#fff;color:#47535d;border-radius:3px;padding:6px 10px;cursor:pointer;white-space:nowrap}.tool-btn:hover{border-color:#8f9ca5;background:#f5f7f8}.tool-btn.primary{background:var(--yellow);border-color:var(--yellow2);color:#25303a;font-weight:700}.filter-select{height:29px;border:1px solid #c8cfd5;background:white;border-radius:3px;padding:3px 7px;color:#4c5863}
.page{display:none}.page.active{display:block}.page-heading{display:flex;justify-content:space-between;align-items:end;margin:17px 2px 15px}.eyebrow{font-size:10px;color:#9ba2a8;letter-spacing:.12em;font-weight:700;margin-bottom:4px}.page-heading h1{font-size:21px;font-weight:500;color:#303c46;margin:0}.page-meta{font-size:11px;color:#9aa1a7}.stat-grid{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:10px;margin-bottom:13px}.stat-card{background:#fff;border:1px solid var(--line);border-top:3px solid #aab4bc;box-shadow:var(--shadow);padding:12px 14px;min-width:0}.stat-card.green{border-top-color:#20945c}.stat-card.blue{border-top-color:#2692c8}.stat-card.orange{border-top-color:#d49528}.stat-label{font-size:11px;color:#7e8992;text-transform:uppercase;letter-spacing:.04em}.stat-value{font-size:25px;color:#2d3a45;margin:5px 0 2px;font-weight:600;font-variant-numeric:tabular-nums}.stat-sub{font-size:11px;color:#99a1a8;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dashboard-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-bottom:12px}.dashboard-grid-main{grid-template-columns:minmax(360px,1.05fr) minmax(340px,.95fr)}.panel{background:var(--panel);border:1px solid #cfd4d8;box-shadow:var(--shadow);margin:0 0 12px;min-width:0}.panel-heading{height:31px;background:var(--head);border-bottom:1px solid #c4c9cd;padding:0 8px;display:flex;align-items:center;justify-content:space-between}.panel-title{font-weight:700;color:#58636c;font-size:12px}.panel-tools{display:flex;align-items:center;gap:7px}.row-count{font-size:10px;color:#7e878e;border:1px solid #c4c9ce;background:#e9ebed;border-radius:10px;padding:2px 7px}.icon-button{border:0;background:transparent;color:#7b858d;font-size:17px;line-height:18px;cursor:pointer;padding:0 2px}.icon-button:hover{color:#26343f}.panel-body{padding:10px}.panel-note{background:#f7f8f9;padding:7px 10px;border-bottom:1px solid #e2e5e8;color:#7d878e;font-size:11px}.panel.collapsed .panel-body,.panel.collapsed .table-wrap,.panel.collapsed .panel-note{display:none}.kv-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 22px;margin:0}.kv-item{display:grid;grid-template-columns:minmax(118px,.9fr) minmax(90px,1fr);gap:8px;padding:7px 1px;border-bottom:1px solid #eff1f2;min-width:0}.kv-item dt{color:#8b949b;font-size:11px;text-align:right}.kv-item dd{margin:0;color:#384550;font-weight:600;overflow-wrap:anywhere}.table-wrap{width:100%;overflow:auto;max-height:75vh}.data-table{width:100%;border-collapse:collapse;table-layout:auto;min-width:650px}.data-table th{position:sticky;top:0;background:#f4f5f6;color:#828b92;text-align:left;text-transform:uppercase;letter-spacing:.025em;font-size:10px;padding:9px 9px;border-bottom:1px solid #cfd4d8;white-space:nowrap;cursor:pointer;user-select:none}.data-table th:hover{color:#3c4b56;background:#eceff1}.data-table td{padding:8px 9px;border-bottom:1px solid #e7eaec;vertical-align:top;font-size:11.5px;line-height:1.45;overflow-wrap:anywhere}.data-table tbody tr:hover{background:#f5f8fa}.data-table tbody tr:last-child td{border-bottom:0}.data-table td strong{font-size:11.5px;color:#35434e}.sort-mark{padding-left:5px;color:#c1c7cc}.data-table th[aria-sort="ascending"] .sort-mark:after{content:"▲"}.data-table th[aria-sort="descending"] .sort-mark:after{content:"▼"}.mono{font-family:Consolas,Monaco,monospace;color:#53616b;font-size:11px;overflow-wrap:anywhere}.subline{display:block;color:#919aa1;font-size:10px;margin-top:3px}.empty-cell{text-align:center!important;color:#9aa2a8;padding:24px!important}.pill{display:inline-block;border:1px solid #d5dbe0;border-radius:3px;padding:2px 6px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.025em;white-space:nowrap;background:#eef1f3;color:#68747d}.pill.good{color:#167248;background:#e6f4ed;border-color:#c9e6d6}.pill.bad{color:#b4332c;background:#fae9e7;border-color:#efcbc7}.pill.warn{color:#9b650b;background:#fff3d9;border-color:#f0dfb5}.pill.blue{color:#1478a8;background:#e6f3f9;border-color:#c6e2ef}.pill.muted{color:#889198;background:#f0f1f2;border-color:#e2e5e7}.pill.neutral{color:#5b6872;background:#edf0f2;border-color:#d9dfe3}.disabled-row{opacity:.55;text-decoration:line-through}.risky-row{background:#fff0ee!important;box-shadow:inset 4px 0 #c84037}.route-line{display:block;padding:2px 0;border-bottom:1px dashed #edf0f1}.runtime-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px}.runtime-item{padding:11px;border:1px solid #e0e4e7;background:#fbfcfc;min-width:0}.runtime-label{display:block;color:#929ba2;font-size:10px;text-transform:uppercase;letter-spacing:.04em;margin-bottom:7px}.runtime-item strong{display:block;color:#818a91;font-size:14px;margin-bottom:5px}.runtime-item small{display:block;color:#9aa2a8;font-size:10px;line-height:1.4}.chart-block{display:flex;align-items:center;gap:28px;min-height:150px;padding:10px 18px}.donut{--a:calc(var(--allow)/var(--total)*100%);width:126px;height:126px;border-radius:50%;background:conic-gradient(#20945c 0 var(--a),#c64b44 var(--a) 100%);display:grid;place-items:center;position:relative;flex:0 0 auto}.donut:before{content:"";position:absolute;width:82px;height:82px;background:white;border-radius:50%}.donut-center{z-index:1;text-align:center}.donut-center strong{display:block;font-size:23px;color:#35424d}.donut-center span{font-size:9px;color:#929ba2;letter-spacing:.1em}.legend{display:grid;gap:9px;color:#6e7982;font-size:11px}.legend span{display:flex;align-items:center;gap:7px}.legend b{margin-left:8px;color:#33414b}.dot{width:8px;height:8px;border-radius:50%;display:inline-block}.dot.allow{background:#20945c}.dot.deny{background:#c64b44}.dot.disabled-dot{background:#aab2b8}.notice{padding:12px 15px;margin-bottom:13px;border:1px solid #d6dce0;background:#fff}.notice strong{display:block;margin-bottom:4px}.notice p{margin:0;color:#68747c;font-size:12px;line-height:1.55}.notice-info{border-left:4px solid #2792bf}.notice-warning{border-left:4px solid #d59a2c}.footer{padding:13px 3px;color:#9ba3a9;font-size:10px;display:flex;justify-content:space-between;border-top:1px solid #d7dbde;margin-top:15px}.toast{position:fixed;bottom:18px;right:18px;background:#26343e;color:white;padding:10px 15px;border-radius:4px;box-shadow:0 3px 14px #0003;z-index:50;opacity:0;transform:translateY(8px);transition:.2s;pointer-events:none}.toast.show{opacity:1;transform:translateY(0)}
@media(max-width:1250px){.stat-grid{grid-template-columns:repeat(3,minmax(130px,1fr))}.dashboard-grid-main{grid-template-columns:1fr 1fr}.topnav button{padding:0 9px}}
@media(max-width:900px){:root{--sidebar:185px}.dashboard-grid,.dashboard-grid-main{grid-template-columns:1fr}.toolbar{position:static}.main{padding:0 9px 18px}.toolbar{margin:0 -9px 10px;padding:0 9px}.topbar{gap:10px;padding:0 10px}.brand{min-width:auto}.topnav button{padding:0 8px;font-size:11px}.topbar-right{display:none}}
@media(max-width:650px){.layout{grid-template-columns:1fr}.sidebar{position:static;height:auto;display:flex;overflow:auto;padding:5px;gap:3px;border-right:0;border-bottom:1px solid var(--line)}.sidebar-caption,.nav-group-label{display:none}.side-link{width:auto;white-space:nowrap;padding:8px;border:0}.side-link.active{border-bottom:2px solid var(--yellow)}.nav-count{display:none}.topbar{height:auto;min-height:54px;flex-wrap:wrap}.topnav{order:3;width:100%;height:35px}.toolbar{height:auto;min-height:42px;flex-wrap:wrap;padding:7px}.search-wrap{margin-left:0;width:100%}.search-wrap input{width:100%;flex:1}.stat-grid{grid-template-columns:repeat(2,minmax(120px,1fr))}.kv-grid{grid-template-columns:1fr}.kv-item{grid-template-columns:125px 1fr}.runtime-grid{grid-template-columns:1fr}.page-heading h1{font-size:18px}.page-meta{display:none}}

/* Interactive XML/object inspection additions */
.object-inspector{position:fixed;z-index:100;display:none;max-width:420px;max-height:55vh;overflow:auto;background:#17232d;color:#edf3f7;border:1px solid #566773;border-radius:5px;padding:10px 12px;box-shadow:0 8px 28px #0004;font-size:12px;pointer-events:none}
.object-inspector strong{color:#ffd24a}.object-inspector .ipline{font-family:Consolas,monospace;color:#8fe0b4;margin:4px 0;overflow-wrap:anywhere}
.xml-modal{display:none;position:fixed;inset:0;z-index:110;background:#101820b8;padding:3vh 3vw;align-items:center;justify-content:center}
.xml-modal.open{display:flex}.xml-dialog{width:min(1200px,96vw);height:94vh;background:#f7f8f9;border:1px solid #9ba8b2;border-radius:6px;display:flex;flex-direction:column;box-shadow:0 15px 60px #0006}
.xml-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#26343e;color:#fff}.xml-head strong{margin-right:auto}.xml-meta{padding:8px 14px;background:#e8edf0;border-bottom:1px solid #ccd4d9;font-size:12px;overflow-wrap:anywhere}
.xml-editor{flex:1;min-height:0;width:100%;resize:none;border:0;padding:14px;background:#101820;color:#dce7ee;font:12px/1.5 Consolas,Monaco,monospace;tab-size:2;white-space:pre;overflow:auto}
.xml-foot{padding:9px 14px;display:flex;gap:8px;align-items:center;background:#e8edf0}.xml-foot .hint{margin-right:auto;color:#66737c;font-size:11px}
tr[data-xml-inspect]{cursor:context-menu}tr[data-xml-inspect]:hover td:first-child{box-shadow:inset 3px 0 #f0b900}

@media print{.topbar,.sidebar,.toolbar,.icon-button{display:none!important}.layout{display:block}.main{padding:0}.page{display:block!important;break-before:page}.page:first-child{break-before:auto}.panel{break-inside:avoid;box-shadow:none}.table-wrap{max-height:none;overflow:visible}.data-table th{position:static}.data-table{min-width:0}.footer{display:none}}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand"><span class="brand-mark">P</span><span>PA-View</span><small style="font-size:10px;color:#9da8b1;font-weight:400">__VERSION__</small></div>
  <nav class="topnav" aria-label="Main navigation">
    <button class="active" data-target="dashboard">DASHBOARD</button><button data-target="monitor">ACC</button><button data-target="monitor">MONITOR</button><button data-target="policies">POLICIES</button><button data-target="objects">OBJECTS</button><button data-target="network">NETWORK</button><button data-target="device">DEVICE</button>
  </nav>
  <div class="topbar-right"><span class="readonly">READ ONLY · XML</span><span>__HOST__</span></div>
</header>
<div class="layout">
  <aside class="sidebar"><div class="sidebar-caption">CONFIGURATION MENU</div>__NAV__</aside>
  <main class="main">
    <div class="toolbar"><span class="toolbar-label">View</span><span id="breadcrumb" class="toolbar-label">Dashboard</span><div class="search-wrap"><input id="globalSearch" type="search" placeholder="Search in current section…" autocomplete="off" aria-label="Search current section"><select id="filterMode" class="filter-select" aria-label="Row filter"><option value="all">All rows</option><option value="risk">Potential risks</option><option value="disabled">Disabled</option><option value="unused">Unused objects</option></select><button class="tool-btn" type="button" onclick="clearFilters()">Clear</button><button class="tool-btn" type="button" onclick="exportCSV()">Export CSV</button><button class="tool-btn" type="button" onclick="exportJSON()">Export JSON</button><button class="tool-btn primary" type="button" onclick="window.print()">Print</button></div></div>
    __PAGES__
    <div class="footer"><span>PA-View · Read-only PAN-OS XML configuration analyzer</span><span>Generated: __GENERATED__ · __SOURCE__</span></div>
  </main>
</div>
<div class="object-inspector" id="objectInspector"></div>
<div class="xml-modal" id="xmlModal" role="dialog" aria-modal="true" aria-label="XML editor">
 <div class="xml-dialog">
  <div class="xml-head"><strong>XML Inspector / Editor</strong><button class="tool-btn" type="button" onclick="closeXmlEditor()">Close ✕</button></div>
  <div class="xml-meta" id="xmlPathMeta">XML path: —</div>
  <textarea class="xml-editor" id="xmlEditor" spellcheck="false" aria-label="XML editor"></textarea>
  <div class="xml-foot"><span class="hint">You are editing a copy in the report. The original file is not overwritten automatically.</span><button class="tool-btn" type="button" onclick="formatXmlEditor()">Format XML</button><button class="tool-btn primary" type="button" onclick="downloadEditedXml()">Download XML</button></div>
 </div>
</div>
<div id="toast" class="toast" role="status" aria-live="polite"></div>
<script id="report-data" type="application/json">__JSON__</script>
<script>
'use strict';
const REPORT = JSON.parse(document.getElementById('report-data').textContent);
let activePage = 'dashboard';
let sortState = {table:null, column:-1, direction:1};
const pageNames = {dashboard:'Dashboard',monitor:'Monitor',policies:'Policies',objects:'Objects',network:'Network',vpn:'IPSec VPN & Crypto',profiles:'Security Profiles',device:'Device / Setup'};
function showToast(message){const el=document.getElementById('toast');el.textContent=message;el.classList.add('show');window.setTimeout(()=>el.classList.remove('show'),2200);}
function activatePage(id){if(!pageNames[id]) return;activePage=id;document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.dataset.page===id));document.querySelectorAll('.side-link,.topnav button').forEach(b=>b.classList.toggle('active',b.dataset.target===id));document.getElementById('breadcrumb').textContent=pageNames[id];document.getElementById('globalSearch').value='';document.getElementById('filterMode').value='all';applyFilters();try{history.replaceState(null,'','#'+id);}catch(e){location.hash=id;}}
document.querySelectorAll('[data-target]').forEach(button=>button.addEventListener('click',()=>activatePage(button.dataset.target)));
function currentPage(){return document.querySelector('.page.active');}
function applyFilters(){const page=currentPage();if(!page)return;const query=document.getElementById('globalSearch').value.trim().toLocaleLowerCase();const mode=document.getElementById('filterMode').value;page.querySelectorAll('tbody tr').forEach(row=>{const text=(row.innerText||'').toLocaleLowerCase();let visible=!query||text.includes(query);if(mode==='risk')visible=visible&&row.dataset.risk==='true';if(mode==='disabled')visible=visible&&row.classList.contains('disabled-row');if(mode==='unused')visible=visible&&text.includes('unused');row.hidden=!visible;});page.querySelectorAll('.panel').forEach(panel=>{const count=panel.querySelectorAll('tbody tr:not([hidden])').length;const badge=panel.querySelector('.row-count');if(badge&&panel.querySelector('table'))badge.textContent=String(count);});}
document.getElementById('globalSearch').addEventListener('input',applyFilters);
document.getElementById('filterMode').addEventListener('change',applyFilters);
function clearFilters(){document.getElementById('globalSearch').value='';document.getElementById('filterMode').value='all';applyFilters();}
function togglePanel(button){const panel=button.closest('.panel');if(!panel)return;panel.classList.toggle('collapsed');button.textContent=panel.classList.contains('collapsed')?'+':'−';}
function refreshPanel(button){const panel=button.closest('.panel');if(!panel)return;panel.querySelectorAll('tbody tr').forEach(row=>row.hidden=false);applyFilters();showToast('Panel refreshed');}
function csvEscape(value){return '"'+String(value??'').replace(/"/g,'""')+'"';}
function exportCSV(){const page=currentPage();if(!page){showToast('No active section');return;}const tables=[...page.querySelectorAll('table')];let lines=[];tables.forEach((table,index)=>{if(index)lines.push('');const title=table.closest('.panel')?.querySelector('.panel-title')?.innerText||'Table';lines.push(csvEscape(title));const headers=[...table.querySelectorAll('thead th')].map(th=>csvEscape(th.innerText.replace(/[▲▼]/g,'').trim()));if(headers.length)lines.push(headers.join(';'));table.querySelectorAll('tbody tr:not([hidden])').forEach(row=>{if(row.querySelector('.empty-cell'))return;lines.push([...row.querySelectorAll('td')].map(td=>csvEscape(td.innerText.trim())).join(';'));});});if(!lines.length){showToast('No data to export');return;}downloadBlob('\ufeff'+lines.join('\r\n'),'pa-view-'+activePage+'.csv','text/csv;charset=utf-8');showToast('Current section exported as CSV');}
function exportJSON(){downloadBlob(JSON.stringify(REPORT,null,2),'pa-view-report.json','application/json;charset=utf-8');showToast('Full report exported as JSON');}
function downloadBlob(content,name,type){const blob=new Blob([content],{type});const url=URL.createObjectURL(blob);const link=document.createElement('a');link.href=url;link.download=name;document.body.appendChild(link);link.click();link.remove();window.setTimeout(()=>URL.revokeObjectURL(url),1500);}
document.querySelectorAll('.data-table thead th').forEach(th=>th.addEventListener('click',()=>{const table=th.closest('table');const index=[...th.parentElement.children].indexOf(th);const body=table.querySelector('tbody');const same=sortState.table===table&&sortState.column===index;const direction=same?-sortState.direction:1;sortState={table,column:index,direction};table.querySelectorAll('th').forEach(h=>{h.removeAttribute('aria-sort');});th.setAttribute('aria-sort',direction===1?'ascending':'descending');const rows=[...body.querySelectorAll('tr')];rows.sort((a,b)=>{const av=a.children[index]?.innerText.trim()||'';const bv=b.children[index]?.innerText.trim()||'';const an=Number(av.replace(/[^0-9.-]/g,''));const bn=Number(bv.replace(/[^0-9.-]/g,''));const numeric=av!==''&&bv!==''&&Number.isFinite(an)&&Number.isFinite(bn)&&/^[\d\s.,%-]+$/.test(av)&&/^[\d\s.,%-]+$/.test(bv);return (numeric?an-bn:av.localeCompare(bv,undefined,{numeric:true,sensitivity:'base'}))*direction;});rows.forEach(row=>body.appendChild(row));applyFilters();}));

// --- PA-View 2.1: object hover, XML path lookup and safe client-side editing ---
const sourceXml=__SOURCE_XML__;
const inspector=document.getElementById('objectInspector');
const xmlModal=document.getElementById('xmlModal');
const xmlEditor=document.getElementById('xmlEditor');
let selectedXmlPath='';
let xmlDoc=null;
try{if(sourceXml.trim())xmlDoc=new DOMParser().parseFromString(sourceXml,'application/xml');}catch(e){}
function xmlPathFor(el){
 if(!el||el.nodeType!==1)return '';
 const parts=[];let cur=el;
 while(cur&&cur.nodeType===1){
  let part=cur.tagName.toLowerCase();
  if(cur.hasAttribute('name'))part+=`[@name="${cur.getAttribute('name')}"]`;
  else if(cur.parentElement){const siblings=[...cur.parentElement.children].filter(x=>x.tagName===cur.tagName);if(siblings.length>1)part+=`[${siblings.indexOf(cur)+1}]`;}
  parts.unshift(part);cur=cur.parentElement;
 }
 return '/'+parts.join('/');
}
function findXmlElement(label,kind){
 if(!xmlDoc||!label)return null;
 const all=[...xmlDoc.getElementsByTagName('*')];
 // Prefer PAN-OS entry elements named exactly as displayed in the row.
 let candidates=all.filter(el=>el.tagName.toLowerCase()==='entry'&&el.getAttribute('name')===label);
 if(!candidates.length)candidates=all.filter(el=>el.getAttribute('name')===label);
 if(kind==='policy'){
  const rule=candidates.find(el=>el.parentElement?.tagName.toLowerCase()==='rules');
  if(rule)return rule;
 }
 return candidates[0]||null;
}
function objectMatches(rowText){
 const objs=(REPORT?.objects?.addresses)||[];
 return objs.filter(o=>o.name&&rowText.includes(o.name));
}
function showInspector(row,ev){
 const txt=row.innerText||'', matches=objectMatches(txt);
 if(!matches.length)return hideInspector();
 inspector.innerHTML='<strong>Address objects associated with this rule</strong>'+matches.slice(0,12).map(o=>`<div><b>${escapeText(o.name)}</b><div class="ipline">${escapeText(o.value||'No IP/FQDN value')}</div><small>${escapeText(o.type||'')}</small></div>`).join('');
 inspector.style.display='block';
 const x=Math.min(ev.clientX+14,window.innerWidth-440),y=Math.min(ev.clientY+14,window.innerHeight-260);
 inspector.style.left=Math.max(8,x)+'px';inspector.style.top=Math.max(8,y)+'px';
}
function hideInspector(){inspector.style.display='none'}
function escapeText(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function openXmlForRow(row){
 const first=row.querySelector('td strong');
 const label=first?.innerText?.trim()||'';
 const isPolicy=!!row.closest('#page-policies')||/policy|rule/i.test(row.closest('.panel')?.innerText?.slice(0,80)||'');
 let el=findXmlElement(label,isPolicy?'policy':'object');
 if(!el){
  // Try name extracted from the entire row (policy/object labels).
  el=findXmlElement(label,'object');
 }
 selectedXmlPath=el?xmlPathFor(el):'Element could not be uniquely identified — use Ctrl+F in the XML.';
 document.getElementById('xmlPathMeta').textContent='Element: '+label+' | XPath-like: '+selectedXmlPath;
 xmlEditor.value=sourceXml;
 xmlModal.classList.add('open');
 if(el){
  const marker=el.getAttribute('name')||label;
  const pos=xmlEditor.value.indexOf(`name="${marker}"`);
  if(pos>=0){xmlEditor.focus();xmlEditor.setSelectionRange(pos,Math.min(pos+marker.length+7,pos+120));}
 }
}
function closeXmlEditor(){xmlModal.classList.remove('open');}
function formatXmlEditor(){
 try{
  const doc=new DOMParser().parseFromString(xmlEditor.value,'application/xml');
  if(doc.querySelector('parsererror')){showToast('XML contains a syntax error; formatting was not applied.');return;}
  const serializer=new XMLSerializer().serializeToString(doc);
  xmlEditor.value=prettyXml(serializer);showToast('XML formatted.');
 }catch(e){showToast('Failed to format XML.');}
}
function prettyXml(xml){
 let formatted='',pad=0;
 xml.replace(/(>)(<)(\/*)/g,'$1\\n$2$3').split('\\n').forEach(line=>{
  if(line.match(/^<\/\w/))pad=Math.max(0,pad-1);
  formatted+='  '.repeat(pad)+line+'\\n';
  if(line.match(/^<[^!?/][^>]*[^/]>$/))pad++;
 });
 return formatted.trim();
}
function downloadEditedXml(){
 const blob=new Blob([xmlEditor.value],{type:'application/xml;charset=utf-8'});
 const url=URL.createObjectURL(blob),a=document.createElement('a');
 a.href=url;a.download='PA-View-edited-config.xml';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
 showToast('The modified XML is ready to download.');
}
document.addEventListener('mouseover',ev=>{
 const row=ev.target.closest?.('.data-table tbody tr');
 if(row&&row.querySelector('td strong'))showInspector(row,ev);
});
document.addEventListener('mouseout',ev=>{
 if(ev.target.closest?.('.data-table tbody tr'))hideInspector();
});
document.addEventListener('click',ev=>{
 const row=ev.target.closest?.('.data-table tbody tr');
 if(row&&row.querySelector('td strong')&&!ev.target.closest('button,a'))openXmlForRow(row);
});
document.addEventListener('keydown',ev=>{if(ev.key==='Escape')closeXmlEditor();});
xmlModal.addEventListener('click',ev=>{if(ev.target===xmlModal)closeXmlEditor();});

const initial=(location.hash||'').slice(1);if(pageNames[initial])activatePage(initial);else applyFilters();
</script>
</body></html>'''
    replacements = {
        "__TITLE__": esc(title), "__VERSION__": esc(data["app_version"]),
        "__HOST__": esc(data["device_info"].get("hostname", "Palo Alto")),
        "__NAV__": nav_html, "__PAGES__": pages_html,
        "__GENERATED__": esc(data["generated_at"]), "__SOURCE__": esc(data["source_file"]),
        "__JSON__": safe_json, "__SOURCE_XML__": safe_xml,
    }
    token_pattern = re.compile("|".join(re.escape(key) for key in replacements))
    content = token_pattern.sub(lambda match: replacements[match.group(0)], template)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")


def parse_palo_alto_config(xml_file_path: str | os.PathLike[str], output_path: str | None = None,
                           open_report: bool = False) -> str:
    """Backward-compatible main entry point. Returns the generated HTML path."""
    print(f"[PA-View] Loading configuration: {xml_file_path}")
    data = _parse_config(xml_file_path)
    destination = Path(output_path) if output_path else Path(xml_file_path).with_name(Path(xml_file_path).stem + "_xml_view.html")
    generate_html(destination, data)
    print(f"[PA-View] Report generated: {destination}")
    if open_report:
        webbrowser.open(destination.resolve().as_uri())
    return str(destination)


def _choose_file() -> str | None:
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        filename = filedialog.askopenfilename(
            title="Select PA config (XML)",
            filetypes=[("XML configuration", "*.xml"), ("All files", "*.*")],
        )
        root.destroy()
        return filename or None
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PA-View - read-only Palo Alto Networks PAN-OS XML configuration viewer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("config_file", nargs="?", help="Path to running-config.xml / exported configuration XML")
    parser.add_argument("-o", "--output", help="Destination path for the HTML report")
    parser.add_argument("--open", action="store_true", help="Open the generated report in the default browser")
    parser.add_argument("--no-gui", action="store_true", help="Do not show the file picker when no argument is provided")
    parser.add_argument("--version", action="version", version=f"PA-View {APP_VERSION}")
    args = parser.parse_args(argv)

    config_file = args.config_file
    selected_via_gui = not bool(config_file) and not args.no_gui
    if selected_via_gui:
        config_file = _choose_file()
    if not config_file:
        parser.print_help()
        print("\nNo XML file was selected.", file=sys.stderr)
        return 2
    try:
        parse_palo_alto_config(config_file, args.output, args.open or selected_via_gui)
        return 0
    except (FileNotFoundError, PermissionError, ValueError, OSError) as exc:
        print(f"[PA-View] ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[PA-View] Unexpected error: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
