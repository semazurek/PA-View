import sys
import os
import xml.etree.ElementTree as ET
import argparse
import traceback

def get_members(element, path):
    if element is None: return "any"
    members = [m.text for m in element.findall(f"{path}/member") if m.text is not None]
    return ", ".join(members) if members else "any"

def get_text(element, path, default="N/A"):
    if element is None: return default
    node = element.find(path)
    return node.text if node is not None and node.text else default

def parse_palo_alto_config(xml_file_path):
    if not os.path.exists(xml_file_path):
        print(f"Error: File '{xml_file_path}' does not exist.")
        return

    print(f"Loading and parsing massive config: {xml_file_path}...")
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
    except Exception as e:
        print(f"Failed to parse XML: {e}")
        return

    # --- 1. SYSTEM & ADMINS & HA ---
    device_info = {
        "hostname": get_text(root, ".//deviceconfig/system/hostname", "N/A"),
        "ip_address": get_text(root, ".//deviceconfig/system/ip-address", "N/A"),
        "netmask": get_text(root, ".//deviceconfig/system/netmask", "N/A"),
        "default_gateway": get_text(root, ".//deviceconfig/system/default-gateway", "N/A"),
        "dns_primary": get_text(root, ".//deviceconfig/system/dns-setting/servers/primary", "N/A"),
        "dns_secondary": get_text(root, ".//deviceconfig/system/dns-setting/servers/secondary", "N/A"),
        "panorama_server": get_text(root, ".//deviceconfig/system/panorama-server", "N/A"),
        "ha_enabled": "Yes" if root.find(".//deviceconfig/high-availability") is not None else "No",
        "ha_peer_ip": get_text(root, ".//deviceconfig/high-availability/interface/ha1/ip-address", "N/A")
    }
    
    admins = []
    for user in root.findall(".//mgt-config/users/entry"):
        admins.append({
            "name": user.attrib.get('name', 'N/A'),
            "role": "Superuser" if user.find("./permissions/role-based/superuser") is not None else "Role-Based"
        })

    # --- 2. NETWORK (Interfaces, Zones, Routers, GlobalProtect) ---
    interfaces = []
    def parse_intf(node, i_type, parent_name=""):
        name = node.attrib.get('name', 'N/A')
        if parent_name: name = f"{parent_name}.{name}"
        ip_addrs = [m.text for m in node.findall(".//ip/entry") if m.text is not None]
        mgmt_prof = get_text(node, ".//interface-management-profile", "None")
        mtu = get_text(node, ".//mtu", "Default")
        vlan_tag = get_text(node, "./tag", "None")
        interfaces.append({
            "name": name, "type": i_type, "ip": ", ".join(ip_addrs) if ip_addrs else "N/A",
            "mgmt": mgmt_prof, "mtu": mtu, "vlan": vlan_tag
        })

    for eth in root.findall(".//network/interface/ethernet/entry"):
        parse_intf(eth, "Ethernet")
        for sub in eth.findall(".//layer3/units/entry"):
            parse_intf(sub, "Subinterface", eth.attrib.get('name', ''))
            
    for if_type in ['loopback', 'tunnel', 'vlan']:
        for entry in root.findall(f".//network/interface/{if_type}/units/entry"):
            parse_intf(entry, if_type.capitalize())

    zones = []
    for z in root.findall(".//vsys/entry/zone/entry"):
        zones.append({
            "name": z.attrib.get('name', 'N/A'),
            "type": get_text(z, "./network/layer3", "Layer3") if z.find("./network/layer3") is not None else "Other",
            "interfaces": get_members(z, "./network/layer3")
        })

    routers = []
    for vr in root.findall(".//network/virtual-router/entry"):
        rts = []
        for route in vr.findall(".//routing-table/ip/static-route/entry"):
            dest = get_text(route, "./destination", "N/A")
            nexthop = get_text(route, "./nexthop/ip-address", get_text(route, "./nexthop/interface", "N/A"))
            rts.append(f"{route.attrib.get('name', 'N/A')}: {dest} &rarr; {nexthop}")
            
        bgp_id = get_text(vr, ".//protocol/bgp/router-id", "N/A")
        ospf_id = get_text(vr, ".//protocol/ospf/router-id", "N/A")
        protocols = []
        if bgp_id != "N/A": protocols.append(f"BGP (ID: {bgp_id})")
        if ospf_id != "N/A": protocols.append(f"OSPF (ID: {ospf_id})")
        
        routers.append({
            "name": vr.attrib.get('name', 'N/A'), 
            "interfaces": get_members(vr, "./interface"), 
            "routes": rts,
            "protocols": ", ".join(protocols) if protocols else "Static Only"
        })

    global_protect = {"portals": [], "gateways": []}
    for gp in root.findall(".//global-protect/global-protect-portal/entry"):
        global_protect["portals"].append({
            "name": gp.attrib.get('name', 'N/A'),
            "auth_profile": get_text(gp, ".//client-auth/entry/auth-profile", "N/A")
        })
    for gw in root.findall(".//global-protect/global-protect-gateway/entry"):
        global_protect["gateways"].append({
            "name": gw.attrib.get('name', 'N/A'),
            "ip_pool": get_text(gw, ".//ip-pool/member", "N/A")
        })

    # --- 3. VPN & CRYPTO (IKE & IPSec, Crypto Profiles) ---
    vpns = {"ike": [], "ipsec": [], "crypto_ike": [], "crypto_ipsec": []}
    for ike in root.findall(".//network/ike/gateway/entry"):
        vpns["ike"].append({
            "name": ike.attrib.get('name', 'N/A'),
            "interface": get_text(ike, "./local-address/interface", "N/A"),
            "peer_ip": get_text(ike, "./peer-address/ip", "N/A"),
            "profile": get_text(ike, "./protocol/ikev1/dpd/crypto-profile", "default")
        })
    for tunnel in root.findall(".//network/tunnel/ipsec/entry"):
        vpns["ipsec"].append({
            "name": tunnel.attrib.get('name', 'N/A'),
            "interface": get_text(tunnel, "./tunnel-monitor/tunnel-interface", "N/A"),
            "ike_gateway": get_text(tunnel, "./auto-key/ike-gateway/entry", "N/A"),
            "profile": get_text(tunnel, "./auto-key/ipsec-crypto-profile", "default")
        })
    for c_ike in root.findall(".//network/ike/crypto-profile/ike-crypto-profile/entry"):
        vpns["crypto_ike"].append({
            "name": c_ike.attrib.get('name', 'N/A'),
            "hash": get_members(c_ike, "./hash"),
            "enc": get_members(c_ike, "./encryption"),
            "dh": get_members(c_ike, "./dh-group")
        })
    for c_ipsec in root.findall(".//network/ike/crypto-profile/ipsec-crypto-profile/entry"):
         vpns["crypto_ipsec"].append({
            "name": c_ipsec.attrib.get('name', 'N/A'),
            "auth": get_members(c_ipsec, "./esp/authentication"),
            "enc": get_members(c_ipsec, "./esp/encryption"),
            "dh": get_members(c_ipsec, "./dh-group")
        })

    # --- 4. OBJECTS & CERTIFICATES ---
    objects = {"addresses": [], "addr_groups": [], "services": [], "svc_groups": [], "tags": [], "certs": []}
    
    used_addresses = set()
    used_services = set()
    used_tags = set()

    for addr in root.findall(".//vsys/entry/address/entry"):
        val = get_text(addr, "./ip-netmask", get_text(addr, "./fqdn", get_text(addr, "./ip-range", "N/A")))
        objects["addresses"].append({"name": addr.attrib.get('name', 'N/A'), "value": val, "desc": get_text(addr, "./description", "")})
    for ag in root.findall(".//vsys/entry/address-group/entry"):
        objects["addr_groups"].append({"name": ag.attrib.get('name', 'N/A'), "members": get_members(ag, "./static")})
    for svc in root.findall(".//vsys/entry/service/entry"):
        proto = "tcp" if svc.find("./protocol/tcp") is not None else "udp"
        objects["services"].append({"name": svc.attrib.get('name', 'N/A'), "protocol": proto.upper(), "port": get_text(svc, f"./protocol/{proto}/port", "N/A")})
    for sg in root.findall(".//vsys/entry/service-group/entry"):
        objects["svc_groups"].append({"name": sg.attrib.get('name', 'N/A'), "members": get_members(sg, "./members")})
    for tag in root.findall(".//vsys/entry/tag/entry") + root.findall(".//tag/entry"):
        objects["tags"].append({"name": tag.attrib.get('name', 'N/A'), "color": get_text(tag, "./color", "None")})
        
    for cert in root.findall(".//shared/certificate/entry") + root.findall(".//vsys/entry/certificate/entry"):
        objects["certs"].append({
            "name": cert.attrib.get('name', 'N/A'),
            "subject": get_text(cert, "./subject", "N/A"),
            "issuer": get_text(cert, "./issuer", "N/A")
        })

    # --- 5. POLICIES (Security, NAT, Decryption, PBF) ---
    policies = {"security": [], "nat": [], "decryption": [], "pbf": []}
    for rule in root.findall(".//vsys/entry/rulebase/security/rules/entry") + root.findall(".//pre-rulebase/security/rules/entry") + root.findall(".//post-rulebase/security/rules/entry"):
        src = get_members(rule, "./source")
        dst = get_members(rule, "./destination")
        srv = get_members(rule, "./service")
        tags = get_members(rule, "./tag")
        
        used_addresses.update([s.strip() for s in src.split(',') if s.strip()])
        used_addresses.update([d.strip() for d in dst.split(',') if d.strip()])
        used_services.update([s.strip() for s in srv.split(',') if s.strip()])
        used_tags.update([t.strip() for t in tags.split(',') if t.strip()])

        action = get_text(rule, "./action", "allow")
        
        # FIX: Check multiple profile locations
        prof_group = get_text(rule, "./profile-setting/group/member", "None")
        if prof_group == "None" and rule.find("./profile-setting/profiles") is not None:
            prof_group = "Custom Profiles"
            
        log_fwd = get_text(rule, "./log-setting", "None")
        
        is_risky = False
        if src == "any" and dst == "any" and action == "allow" and prof_group == "None" and log_fwd == "None":
            is_risky = True
            
        policies["security"].append({
            "name": rule.attrib.get('name', 'N/A'),
            "desc": get_text(rule, "./description", ""),
            "tags": tags,
            "users": get_members(rule, "./source-user"),
            "from": get_members(rule, "./from"), "to": get_members(rule, "./to"),
            "source": src, "destination": dst,
            "app": get_members(rule, "./application"), "svc": srv,
            "action": action, "disabled": get_text(rule, "./disabled", "no"),
            "log_fwd": log_fwd,
            "prof_group": prof_group,
            "risky": is_risky
        })
        
    for rule in root.findall(".//vsys/entry/rulebase/nat/rules/entry") + root.findall(".//pre-rulebase/nat/rules/entry"):
        policies["nat"].append({
            "name": rule.attrib.get('name', 'N/A'), "from": get_members(rule, "./from"), "to": get_members(rule, "./to"),
            "source": get_members(rule, "./source"), "destination": get_members(rule, "./destination"), "disabled": get_text(rule, "./disabled", "no")
        })
    for rule in root.findall(".//vsys/entry/rulebase/decryption/rules/entry"):
        policies["decryption"].append({
            "name": rule.attrib.get('name', 'N/A'), "from": get_members(rule, "./from"), "to": get_members(rule, "./to"),
            "source": get_members(rule, "./source"), "destination": get_members(rule, "./destination"), "action": get_text(rule, "./action", "no-decrypt")
        })
    for rule in root.findall(".//vsys/entry/rulebase/pbf/rules/entry"):
         policies["pbf"].append({
            "name": rule.attrib.get('name', 'N/A'), "from": get_members(rule, "./from"),
            "source": get_members(rule, "./source"), "destination": get_members(rule, "./destination"),
            "action": "Forward" if rule.find("./action/forward") is not None else "No PBF",
            "egress": get_text(rule, "./action/forward/egress-interface", "N/A")
        })
         
    for obj in objects["addresses"]:
        obj["orphaned"] = obj["name"] not in used_addresses and obj["name"] != "any"

    # --- 6. PROFILES ---
    profiles = {"av": [], "spyware": [], "vuln": [], "url": [], "wildfire": [], "groups": []}
    for p in root.findall(".//vsys/entry/profiles/virus/entry"): profiles["av"].append(p.attrib.get('name', 'N/A'))
    for p in root.findall(".//vsys/entry/profiles/spyware/entry"): profiles["spyware"].append(p.attrib.get('name', 'N/A'))
    for p in root.findall(".//vsys/entry/profiles/vulnerability/entry"): profiles["vuln"].append(p.attrib.get('name', 'N/A'))
    for p in root.findall(".//vsys/entry/profiles/url-filtering/entry"): profiles["url"].append(p.attrib.get('name', 'N/A'))
    for p in root.findall(".//vsys/entry/profiles/wildfire-analysis/entry"): profiles["wildfire"].append(p.attrib.get('name', 'N/A'))
    for pg in root.findall(".//vsys/entry/profile-group/entry"):
        profiles["groups"].append({
            "name": pg.attrib.get('name', 'N/A'),
            "av": get_members(pg, "./virus"), "spyware": get_members(pg, "./spyware"),
            "vuln": get_members(pg, "./vulnerability"), "url": get_members(pg, "./url-filtering")
        })

    output_html_path = os.path.splitext(xml_file_path)[0] + "_xml_view.html"
    try:
        generate_html(output_html_path, device_info, admins, interfaces, zones, routers, global_protect, vpns, objects, policies, profiles)
        print(f"Success! Report generated at: {output_html_path}")
    except Exception as e:
        print(f"Error generating HTML: {e}")
        traceback.print_exc()

def escape_html(text):
    if not isinstance(text, str):
        return str(text)
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

def generate_html(output_path, device_info, admins, interfaces, zones, routers, global_protect, vpns, objects, policies, profiles):
    # Calculate statistics safely
    allow_count = sum(1 for p in policies['security'] if p['action'] == 'allow')
    deny_count = sum(1 for p in policies['security'] if p['action'] != 'allow')
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Palo Alto XML View</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f0f2f5; margin: 20px; color: #333; }}
        h1 {{ color: #1a252f; margin-bottom: 5px; }}
        .header-sub {{ color: #7f8c8d; margin-top: 0; margin-bottom: 20px; font-size: 14px; }}
        .search-box {{ margin-bottom: 20px; padding: 12px; width: 100%; max-width: 500px; font-size: 15px; border: 1px solid #dcdde1; border-radius: 6px; box-shadow: 0 2px 4px rgba(0,0,0,0.02); display: inline-block; }}
        .btn-export {{ background: #27ae60; color: white; border: none; padding: 12px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; margin-left: 10px; }}
        .btn-export:hover {{ background: #2ecc71; }}
        
        .tab-nav {{ display: flex; flex-wrap: wrap; gap: 5px; border-bottom: 3px solid #2c3e50; margin-bottom: 20px; padding-bottom: 5px; }}
        .tab-btn {{ padding: 10px 20px; border: 1px solid transparent; background: #e8ecef; cursor: pointer; font-size: 14px; font-weight: 600; color: #2c3e50; border-radius: 5px 5px 0 0; transition: 0.2s; }}
        .tab-btn:hover {{ background-color: #d1d8e0; }}
        .tab-btn.active {{ background-color: #2c3e50; color: white; border-color: #2c3e50; box-shadow: 0 -2px 5px rgba(0,0,0,0.1); }}
        .tab-content {{ display: none; background: white; padding: 20px; border-radius: 0 0 8px 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
        .tab-content.active {{ display: block; }}

        h2 {{ border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; color: #2980b9; margin-top: 30px; font-size: 18px; }}
        h2:first-child {{ margin-top: 0; }}
        
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; table-layout: fixed; word-wrap: break-word; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #ecf0f1; font-size: 13.5px; vertical-align: top; }}
        th {{ background-color: #f8f9fa; color: #34495e; text-transform: uppercase; font-size: 12px; border-bottom: 2px solid #bdc3c7; cursor: pointer; }}
        tr:hover {{ background-color: #f1f5f8; }}
        
        .action-allow {{ color: #27ae60; font-weight: bold; background: #e8f8f5; padding: 3px 8px; border-radius: 4px; display: inline-block; }}
        .action-deny, .action-drop, .action-decrypt {{ color: #c0392b; font-weight: bold; background: #fadbd8; padding: 3px 8px; border-radius: 4px; display: inline-block; }}
        .disabled {{ text-decoration: line-through; opacity: 0.5; background: #fdfefe; }}
        .badge {{ background: #eef2f7; padding: 3px 7px; border-radius: 4px; font-family: 'Consolas', monospace; border: 1px solid #d0d7de; font-size: 12.5px; color: #2c3e50; display: inline-block; margin-bottom: 2px; cursor: help; word-break: break-all; }}
        .tag-badge {{ background: #f39c12; color: white; padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold; display: inline-block; margin-right: 2px; margin-bottom: 2px; }}
        .meta-text {{ font-size: 12px; color: #7f8c8d; margin-top: 4px; display: block; }}
        .risky-rule {{ border-left: 4px solid #e74c3c !important; background: #fdf1f0 !important; }}
        .orphaned {{ color: #e67e22; font-style: italic; }}
        .orphaned-badge {{ background: #fdebd0; color: #d35400; padding: 2px 5px; border-radius: 3px; font-size: 10px; margin-left: 5px; }}
        
        .card-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 15px; }}
        .card {{ background: #fdfdfd; padding: 15px; border-radius: 6px; border: 1px solid #e1e4e8; }}
        .card h4 {{ margin: 0 0 5px 0; color: #95a5a6; font-size: 12px; text-transform: uppercase; }}
        .card p {{ margin: 0; font-size: 15px; font-weight: bold; color: #34495e; word-break: break-all; }}
        
        .chart-container {{ max-width: 400px; margin: 20px 0; }}
        
        /* Column Widths for Policies */
        .col-name {{ width: 20%; }}
        .col-src {{ width: 25%; }}
        .col-dst {{ width: 25%; }}
        .col-app {{ width: 15%; }}
        .col-act {{ width: 15%; }}
    </style>
    <!-- Chart.js for visualization -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        function openTab(tabName, btn) {{
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.getElementById(tabName).classList.add("active");
            btn.classList.add("active");
        }}
        function filterContent() {{
            let input = document.getElementById('searchInput').value.toLowerCase();
            let rows = document.querySelectorAll('.tab-content.active tbody tr');
            rows.forEach(row => {{ row.style.display = row.innerText.toLowerCase().includes(input) ? '' : 'none'; }});
        }}
        function exportTableToCSV(filename) {{
            let csv = [];
            let activeTab = document.querySelector('.tab-content.active');
            let rows = activeTab.querySelectorAll("table tr");
            
            for (let i = 0; i < rows.length; i++) {{
                if (rows[i].style.display === 'none') continue;
                let row = [], cols = rows[i].querySelectorAll("td, th");
                for (let j = 0; j < cols.length; j++) {{
                    let text = cols[j].innerText.replace(/"/g, '""');
                    row.push('"' + text + '"');
                }}
                csv.push(row.join(","));
            }}
            let csvFile = new Blob([csv.join("\\n")], {{type: "text/csv"}});
            let downloadLink = document.createElement("a");
            downloadLink.download = filename;
            downloadLink.href = window.URL.createObjectURL(csvFile);
            downloadLink.style.display = "none";
            document.body.appendChild(downloadLink);
            downloadLink.click();
        }}
    </script>
</head>
<body>

    <h1>Palo Alto XML View</h1>
    <p class="header-sub">Advanced Configuration Dashboard & Security Audit</p>
    
    <div>
        <input type="text" id="searchInput" class="search-box" onkeyup="filterContent()" placeholder="Search in active tab (e.g. 192.168.1.1, allow, trust)...">
        <button class="btn-export" onclick="exportTableToCSV('palo_alto_export.csv')">Export Active Table to CSV</button>
    </div>

    <div class="tab-nav">
        <button class="tab-btn active" onclick="openTab('dashboard', this)">Dashboard</button>
        <button class="tab-btn" onclick="openTab('network', this)">Network & GlobalProtect</button>
        <button class="tab-btn" onclick="openTab('vpn', this)">IPSec VPNs & Crypto</button>
        <button class="tab-btn" onclick="openTab('objects', this)">All Objects & Certs</button>
        <button class="tab-btn" onclick="openTab('policies', this)">Security, NAT & PBF</button>
        <button class="tab-btn" onclick="openTab('profiles', this)">Security Profiles</button>
    </div>

    <!-- 1. DASHBOARD -->
    <div id="dashboard" class="tab-content active">
        <h2>System & High Availability</h2>
        <div class="card-grid" style="margin-bottom: 30px;">
            <div class="card"><h4>Hostname</h4><p>{escape_html(device_info['hostname'])}</p></div>
            <div class="card"><h4>Management IP</h4><p>{escape_html(device_info['ip_address'])}</p></div>
            <div class="card"><h4>Gateway</h4><p>{escape_html(device_info['default_gateway'])}</p></div>
            <div class="card"><h4>DNS Primary</h4><p>{escape_html(device_info['dns_primary'])}</p></div>
            <div class="card"><h4>Panorama</h4><p>{escape_html(device_info['panorama_server'])}</p></div>
            <div class="card"><h4>HA Enabled</h4><p>{escape_html(device_info['ha_enabled'])}</p></div>
            <div class="card"><h4>HA Peer IP</h4><p>{escape_html(device_info['ha_peer_ip'])}</p></div>
        </div>
        
        <h2>Policy Statistics</h2>
        <div class="chart-container">
            <canvas id="policyChart"></canvas>
        </div>
        
        <h2>Administrators</h2>
        <table>
            <thead><tr><th>Username</th><th>Role / Permissions</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(a['name'])}</strong></td><td><span class='badge'>{escape_html(a['role'])}</span></td></tr>" for a in admins])}
            </tbody>
        </table>
    </div>

    <!-- 2. NETWORK -->
    <div id="network" class="tab-content">
        <h2>Zones</h2>
        <table>
            <thead><tr><th>Zone Name</th><th>Type</th><th>Assigned Interfaces</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(z['name'])}</strong></td><td>{escape_html(z['type'])}</td><td><span class='badge'>{escape_html(z['interfaces'])}</span></td></tr>" for z in zones])}
            </tbody>
        </table>
        
        <h2>Interfaces & Subinterfaces</h2>
        <table>
            <thead><tr><th>Interface</th><th>Type</th><th>IP Address</th><th>VLAN Tag</th><th>Mgmt Profile</th><th>MTU</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(i['name'])}</strong></td><td>{escape_html(i['type'])}</td><td><span class='badge'>{escape_html(i['ip'])}</span></td><td>{escape_html(i['vlan'])}</td><td>{escape_html(i['mgmt'])}</td><td>{escape_html(i['mtu'])}</td></tr>" for i in interfaces])}
            </tbody>
        </table>

        <h2>Virtual Routers (Routing Protocols & Static Routes)</h2>
        <table>
            <thead><tr><th>Router Name</th><th>Interfaces</th><th>Dynamic Protocols</th><th>Static Routes</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(r['name'])}</strong></td><td>{escape_html(r['interfaces'])}</td><td>{escape_html(r['protocols'])}</td><td>{'<br>'.join(escape_html(rt) for rt in r['routes']) if r['routes'] else 'None'}</td></tr>" for r in routers])}
            </tbody>
        </table>
        
        <h2>GlobalProtect</h2>
        <table>
            <thead><tr><th>Portal/Gateway</th><th>Type</th><th>Config (Auth / IP Pool)</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(p['name'])}</strong></td><td>Portal</td><td>Auth Profile: {escape_html(p['auth_profile'])}</td></tr>" for p in global_protect['portals']])}
                {"".join([f"<tr><td><strong>{escape_html(g['name'])}</strong></td><td>Gateway</td><td>IP Pool: {escape_html(g['ip_pool'])}</td></tr>" for g in global_protect['gateways']])}
            </tbody>
        </table>
    </div>

    <!-- 3. VPN & CRYPTO -->
    <div id="vpn" class="tab-content">
        <h2>IKE Gateways (Phase 1)</h2>
        <table>
            <thead><tr><th>Gateway Name</th><th>Local Interface</th><th>Peer IP</th><th>Crypto Profile</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(v['name'])}</strong></td><td>{escape_html(v['interface'])}</td><td><span class='badge'>{escape_html(v['peer_ip'])}</span></td><td>{escape_html(v['profile'])}</td></tr>" for v in vpns['ike']])}
            </tbody>
        </table>
        
        <h2>IPSec Tunnels (Phase 2)</h2>
        <table>
            <thead><tr><th>Tunnel Name</th><th>Tunnel Interface</th><th>IKE Gateway Bound</th><th>Crypto Profile</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(v['name'])}</strong></td><td>{escape_html(v['interface'])}</td><td>{escape_html(v['ike_gateway'])}</td><td>{escape_html(v['profile'])}</td></tr>" for v in vpns['ipsec']])}
            </tbody>
        </table>
        
        <h2>Crypto Profiles</h2>
        <table>
            <thead><tr><th>Profile Name</th><th>Type</th><th>Encryption</th><th>Hash / Auth</th><th>DH Group</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(c['name'])}</strong></td><td>IKE</td><td>{escape_html(c['enc'])}</td><td>{escape_html(c['hash'])}</td><td>{escape_html(c['dh'])}</td></tr>" for c in vpns['crypto_ike']])}
                {"".join([f"<tr><td><strong>{escape_html(c['name'])}</strong></td><td>IPSec</td><td>{escape_html(c['enc'])}</td><td>{escape_html(c['auth'])}</td><td>{escape_html(c['dh'])}</td></tr>" for c in vpns['crypto_ipsec']])}
            </tbody>
        </table>
    </div>

    <!-- 4. OBJECTS -->
    <div id="objects" class="tab-content">
        <h2>Address Objects & Groups</h2>
        <table>
            <thead><tr><th>Name</th><th>Type</th><th>Value / Members</th></tr></thead>
            <tbody>
                {"".join([f"<tr class='{'orphaned' if a.get('orphaned') else ''}'><td><strong>{escape_html(a['name'])}</strong>{'<span class=\"orphaned-badge\">Unused</span>' if a.get('orphaned') else ''}</td><td>Object</td><td><span class='badge' title='{escape_html(a['desc'])}'>{escape_html(a['value'])}</span></td></tr>" for a in objects['addresses']])}
                {"".join([f"<tr><td><strong>{escape_html(ag['name'])}</strong></td><td><strong>Group</strong></td><td>{escape_html(ag['members'])}</td></tr>" for ag in objects['addr_groups']])}
            </tbody>
        </table>

        <h2>Service Objects & Groups</h2>
        <table>
            <thead><tr><th>Name</th><th>Type</th><th>Protocol / Port / Members</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(s['name'])}</strong></td><td>Service</td><td>{escape_html(s['protocol'])} / <span class='badge'>{escape_html(s['port'])}</span></td></tr>" for s in objects['services']])}
                {"".join([f"<tr><td><strong>{escape_html(sg['name'])}</strong></td><td><strong>Group</strong></td><td>{escape_html(sg['members'])}</td></tr>" for sg in objects['svc_groups']])}
            </tbody>
        </table>
        
        <h2>Certificates</h2>
        <table>
            <thead><tr><th>Certificate Name</th><th>Subject</th><th>Issuer</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(c['name'])}</strong></td><td>{escape_html(c['subject'])}</td><td>{escape_html(c['issuer'])}</td></tr>" for c in objects['certs']])}
            </tbody>
        </table>
    </div>

    <!-- 5. POLICIES -->
    <div id="policies" class="tab-content">
        <h2>Security Policies (Deep View)</h2>
        <p class="meta-text" style="color: #e74c3c;">* Rules highlighted in red indicate potential risks (Any-Any Allow without profiles/logging).</p>
        <table>
            <colgroup>
                <col class="col-name">
                <col class="col-src">
                <col class="col-dst">
                <col class="col-app">
                <col class="col-act">
            </colgroup>
            <thead><tr><th>Rule Name / Details</th><th>Source (Zone / IP / User)</th><th>Destination (Zone / IP)</th><th>App & Service</th><th>Action / Profile / Log</th></tr></thead>
            <tbody>
                {"".join([f"""
                <tr class="{'disabled' if p['disabled']=='yes' else ''} {'risky-rule' if p['risky'] else ''}">
                    <td>
                        <strong>{escape_html(p['name'])}</strong><br>
                        {''.join([f"<span class='tag-badge'>{escape_html(tag)}</span>" for tag in p['tags'].split(', ') if tag != 'any' and tag != 'N/A'])}
                        <span class="meta-text">{escape_html(p['desc'])}</span>
                    </td>
                    <td>
                        <strong>Zone:</strong> <span class="badge">{escape_html(p['from'])}</span><br>
                        <strong>IP:</strong> {escape_html(p['source'])}<br>
                        <strong>User:</strong> {escape_html(p['users'])}
                    </td>
                    <td>
                        <strong>Zone:</strong> <span class="badge">{escape_html(p['to'])}</span><br>
                        <strong>IP:</strong> {escape_html(p['destination'])}
                    </td>
                    <td>
                        <strong>App:</strong> {escape_html(p['app'])}<br>
                        <strong>Svc:</strong> {escape_html(p['svc'])}
                    </td>
                    <td>
                        <span class="{'action-allow' if p['action']=='allow' else 'action-deny'}">{escape_html(p['action'])}</span><br>
                        <span class="meta-text">Prof: {escape_html(p['prof_group'])}</span>
                        <span class="meta-text">Log: {escape_html(p['log_fwd'])}</span>
                    </td>
                </tr>
                """ for p in policies['security']])}
            </tbody>
        </table>

        <h2>NAT & Decryption Policies</h2>
        <table>
            <thead><tr><th>Name</th><th>Type</th><th>From</th><th>To</th><th>Source</th><th>Destination</th></tr></thead>
            <tbody>
                {"".join([f"<tr class=\"{'disabled' if p['disabled']=='yes' else ''}\"><td><strong>{escape_html(p['name'])}</strong></td><td><span class=\"badge\">NAT</span></td><td>{escape_html(p['from'])}</td><td>{escape_html(p['to'])}</td><td>{escape_html(p['source'])}</td><td>{escape_html(p['destination'])}</td></tr>" for p in policies['nat']])}
                {"".join([f"<tr><td><strong>{escape_html(p['name'])}</strong></td><td><span class=\"badge\">Decryption ({escape_html(p['action'])})</span></td><td>{escape_html(p['from'])}</td><td>{escape_html(p['to'])}</td><td>{escape_html(p['source'])}</td><td>{escape_html(p['destination'])}</td></tr>" for p in policies['decryption']])}
            </tbody>
        </table>
        
        <h2>Policy Based Forwarding (PBF)</h2>
        <table>
            <thead><tr><th>Name</th><th>From</th><th>Source</th><th>Destination</th><th>Action & Egress</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(p['name'])}</strong></td><td><span class=\"badge\">{escape_html(p['from'])}</span></td><td>{escape_html(p['source'])}</td><td>{escape_html(p['destination'])}</td><td>{escape_html(p['action'])} -> {escape_html(p['egress'])}</td></tr>" for p in policies['pbf']])}
            </tbody>
        </table>
    </div>

    <!-- 6. PROFILES -->
    <div id="profiles" class="tab-content">
        <h2>Security Profile Groups</h2>
        <table>
            <thead><tr><th>Group Name</th><th>Antivirus</th><th>Anti-Spyware</th><th>Vulnerability</th><th>URL Filtering</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td><strong>{escape_html(pg['name'])}</strong></td><td>{escape_html(pg['av'])}</td><td>{escape_html(pg['spyware'])}</td><td>{escape_html(pg['vuln'])}</td><td>{escape_html(pg['url'])}</td></tr>" for pg in profiles['groups']])}
            </tbody>
        </table>
    </div>

    <script>
        // Chart logic for Dashboard
        const ctx = document.getElementById('policyChart');
        if (ctx) {{
            let allowCount = {allow_count};
            let denyCount = {deny_count};
            new Chart(ctx, {{
                type: 'doughnut',
                data: {{
                    labels: ['Allow Policies', 'Deny/Drop Policies'],
                    datasets: [{{
                        data: [allowCount, denyCount],
                        backgroundColor: ['#2ecc71', '#e74c3c'],
                        borderWidth: 1
                    }}]
                }},
                options: {{ responsive: true, maintainAspectRatio: false }}
            }});
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Palo Alto Advanced XML Config Auditor")
    parser.add_argument("config_file", help="Path to the running-config.xml file")
    args = parser.parse_args()
    parse_palo_alto_config(args.config_file)
