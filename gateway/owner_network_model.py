"""Pure owner-side network validation/planning. No commands, sockets or file writes.

The root PHP collector supplies live metadata. This module runs in the pinned
candidate image with no network and no host mounts. A true proof flag is emitted
only after its corresponding independently collected observations are checked.
"""
import hashlib
import ipaddress
import json
import re
import shlex
import sys
import time

import deployment_policy as dp

PREFIX = "HOME_AI_REACH_"
COMMENT = "home-ai-reach-"
DYNAMIC = {"HOME_AI_REACH_HOST", "HOME_AI_REACH_PRE", "HOME_AI_REACH_NAT"}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(value):
    return dp.digest(value)


def words(line):
    return shlex.split(line)


def parse_rules(raw):
    need(isinstance(raw, str) and len(raw) <= 2097152, "firewall-bound")
    result = {}
    table = None
    for line in raw.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            table = line[1:]
            need(table not in result, "duplicate-table")
            result[table] = {"chains": {}, "rules": {}}
        elif line == "COMMIT":
            table = None
        elif line.startswith(":"):
            need(table is not None, "chain-outside-table")
            name, policy, *_ = line[1:].split()
            need(name not in result[table]["chains"], "duplicate-chain")
            result[table]["chains"][name] = policy
        elif line.startswith("-A "):
            need(table is not None, "rule-outside-table")
            token = words(line)
            result[table]["rules"].setdefault(token[1], []).append(token[2:])
        else:
            raise ValueError("unknown-firewall-record")
    need({"filter", "mangle", "nat"} <= set(result), "required-tables")
    return result


def owned_rule(chain, rule):
    return chain.startswith(PREFIX) or any(PREFIX in x or COMMENT in x for x in rule)


def owned_snapshot(parsed):
    return {table: {
        "chains": sorted(name for name in data["chains"] if name.startswith(PREFIX)),
        "rules": [[chain, rule] for chain, rules in data["rules"].items() for rule in rules
                  if owned_rule(chain, rule)],
    } for table, data in sorted(parsed.items()) if table in ("filter", "mangle", "nat")}


def unowned_digest(parsed):
    return digest({table: {
        "chains": {name: value for name, value in data["chains"].items() if not name.startswith(PREFIX)},
        "rules": {chain: [rule for rule in rules if not owned_rule(chain, rule)]
                  for chain, rules in data["rules"].items() if not chain.startswith(PREFIX)},
    } for table, data in parsed.items()})


def owner_config(value, shared):
    dp.policy(shared)
    dp.exact(value, {"version", "container_name", "network_id", "bridge", "binds",
                     "dns", "github_hosts", "container_spec", "migration_owned_sha256"})
    dp.version(value["version"], 1)
    need(value["container_name"] == "reach-gateway-edge-1", "container-name")
    dp.sha(value["network_id"])
    need(value["bridge"] == "br-" + value["network_id"][:12], "bridge-id")
    need(value["dns"] == ["8.8.8.8"], "dns-policy")
    need(set(value["github_hosts"]) == {"github.com", "api.github.com"}, "oauth-hosts")
    for name, addresses in value["github_hosts"].items():
        need(isinstance(addresses, list) and 1 <= len(addresses) <= 4 and addresses == sorted(set(addresses)), "oauth-addresses")
        need(all(ipaddress.ip_address(x).version == 4 and ipaddress.ip_address(x).is_global
                 for x in addresses), "oauth-address-public")
    need(isinstance(value["binds"], list) and 1 <= len(value["binds"]) <= 4, "bind-count")
    seen = set()
    for bind in value["binds"]:
        dp.exact(bind, {"url", "address", "interface"})
        need(bind["url"] in shared["tls"]["private_urls"], "unapproved-origin")
        ip = ipaddress.ip_address(bind["address"])
        need(ip.version == 4 and not ip.is_loopback and not ip.is_unspecified
             and not ip.is_multicast and str(ip) == bind["address"], "bind-address")
        dp.safe_name(bind["interface"])
        need(bind["url"] not in seen, "duplicate-origin")
        seen.add(bind["url"])
    need(seen == set(shared["tls"]["private_urls"]), "missing-origin")
    need(digest(value["container_spec"]) == shared["container_spec_sha256"], "spec-policy-digest")
    if value["migration_owned_sha256"] is not None:
        dp.sha(value["migration_owned_sha256"])
    return value


def recipes(shared, owner, profiles):
    owner_config(owner, shared)
    enabled = {}
    for selected in profiles:
        dp.profile(selected, shared)
        need(selected["vm_id"] not in enabled, "duplicate-profile")
        if selected["enabled"]:
            enabled[selected["vm_id"]] = selected
    bridge = owner["bridge"]
    subnet = shared["network"]["subnet"]
    container = shared["network"]["container_ip"] + "/32"
    closed = [["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"], ["-j", "DROP"]]
    chains = {
        "filter": {"HOME_AI_REACH_CHOST": closed, "HOME_AI_REACH_CIN": closed,
                   "HOME_AI_REACH_COUT": [closed[0]],
                   "HOME_AI_REACH_HOST": []},
        "mangle": {"HOME_AI_REACH_PRE": []},
        "nat": {"HOME_AI_REACH_NAT": []},
    }
    for protocol in ("udp", "tcp"):
        chains["filter"]["HOME_AI_REACH_COUT"].append(
            ["-s", container, "-d", owner["dns"][0] + "/32", "-i", bridge, "-p", protocol,
             "-m", protocol, "--dport", "53", "-m", "conntrack", "--ctstate", "NEW",
             "-m", "comment", "--comment", COMMENT + "dns-" + protocol + "-v1", "-j", "RETURN"])
    for address in sorted({ip for addresses in owner["github_hosts"].values() for ip in addresses}):
        chains["filter"]["HOME_AI_REACH_COUT"].append(
            ["-s", container, "-d", address + "/32", "-i", bridge, "-p", "tcp", "-m", "tcp",
             "--dport", "443", "-m", "conntrack", "--ctstate", "NEW",
             "-m", "comment", "--comment", COMMENT + "github-v1", "-j", "RETURN"])
    chains["filter"]["HOME_AI_REACH_COUT"].append(["-j", "DROP"])
    hooks = [
        ["filter", "INPUT", ["-s", subnet, "-m", "comment", "--comment", COMMENT + "container-host-v1", "-j", "HOME_AI_REACH_CHOST"]],
        ["filter", "FORWARD", ["-s", subnet, "-m", "comment", "--comment", COMMENT + "egress-v1", "-j", "HOME_AI_REACH_COUT"]],
        ["filter", "FORWARD", ["-d", subnet, "-m", "comment", "--comment", COMMENT + "ingress-v1", "-j", "HOME_AI_REACH_CIN"]],
    ]
    for bind in owner["binds"]:
        match = ["-d", bind["address"] + "/32", "-p", "tcp", "-m", "tcp", "--dport", "19444"]
        for table, chain, comment, target in (
            ("filter", "INPUT", "host-v2", "HOME_AI_REACH_HOST"),
            ("mangle", "PREROUTING", "private-v2", "HOME_AI_REACH_PRE"),
            ("nat", "PREROUTING", "local-v2", "HOME_AI_REACH_NAT"),
        ):
            hooks.append([table, chain, match + ["-m", "comment", "--comment", COMMENT + comment, "-j", target]])
    for vm_id, selected in sorted(enabled.items()):
        bind = next(x for x in owner["binds"] if x["url"] == selected["worker_url"])
        if selected["kind"] == "windows-tailnet":
            need(re.fullmatch(r"tailscale[0-9]{1,6}", bind["interface"])
                 and selected["adapter"]["interface"] == bind["interface"], "tailnet-interface-binding")
        for table, chain in (("filter", "HOME_AI_REACH_HOST"), ("mangle", "HOME_AI_REACH_PRE"), ("nat", "HOME_AI_REACH_NAT")):
            for address in sorted(selected["source_addresses"]):
                chains[table][chain].append(
                    ["-s", address + "/32", "-d", bind["address"] + "/32", "-i", bind["interface"],
                     "-m", "comment", "--comment", "home-ai-reach-vm-" + vm_id,
                     "-j", "ACCEPT" if table == "nat" else "RETURN"])
    # RETURN preserves later host/guest restrictions; only NAT uses ACCEPT to
    # retain Docker's host-listener path instead of destination NAT.
    chains["filter"]["HOME_AI_REACH_HOST"].append(["-j", "DROP"])
    chains["mangle"]["HOME_AI_REACH_PRE"].append(["-j", "DROP"])
    chains["nat"]["HOME_AI_REACH_NAT"].append(["-j", "RETURN"])
    return chains, hooks


def shared_rules_digest(chains, hooks):
    stable = {table: {name: body[-1:] if name in DYNAMIC else body
                      for name, body in values.items()}
              for table, values in chains.items()}
    return digest({"chains": stable, "hooks": hooks})


# The independent operator broker renewer reinstalls this exact rule at NAT
# PREROUTING position 1 every 30 minutes. Its sole TCP destination port19443
# cannot match any Reach private hook (TCP19444). This is an observed host
# coexistence exception, never a VM profile, wildcard predecessor or rule edit.
BROKER_LOCAL_NAT_PREDECESSOR = [
    "-s", "192.0.2.10/32", "-d", "192.0.2.1/32", "-i", "virbr-reach0",
    "-p", "tcp", "-m", "tcp", "--dport", "19443", "-m", "comment",
    "--comment", "reach-private-network-broker-local", "-j", "ACCEPT",
]


def ordered_hook_prefix(table, parent, actual, expected):
    if (table == "nat" and parent == "PREROUTING" and actual
            and actual[0] == BROKER_LOCAL_NAT_PREDECESSOR
            and expected and all(len(rule) == 14 and rule[:1] == ["-d"]
                                 and rule[2:8] == ["-p", "tcp", "-m", "tcp", "--dport", "19444"]
                                 for rule in expected)):
        # Check the actual observed rule; do not normalize or rewrite evidence.
        actual = actual[1:]
    return actual[:len(expected)] == expected


def validate_rules(parsed, chains, hooks, ordering=True):
    expected_names = {table: set(values) for table, values in chains.items()}
    for table in ("filter", "mangle", "nat"):
        actual_names = {name for name in parsed[table]["chains"] if name.startswith(PREFIX)}
        need(actual_names == expected_names[table], "owned-chain-set")
        for chain, body in chains[table].items():
            need(parsed[table]["chains"][chain] == "-", "owned-chain-policy")
            need(parsed[table]["rules"].get(chain, []) == body, "owned-chain-content")
        expected_hooks = [(chain, rule) for t, chain, rule in hooks if t == table]
        actual_hooks = [(chain, rule) for chain, body in parsed[table]["rules"].items()
                        if not chain.startswith(PREFIX) for rule in body if owned_rule(chain, rule)]
        need(sorted(actual_hooks) == sorted(expected_hooks), "owned-hook-set")
        if ordering:
            for parent in {chain for chain, _ in expected_hooks}:
                expected = [rule for chain, rule in expected_hooks if chain == parent]
                actual = parsed[table]["rules"].get(parent, [])
                need(ordered_hook_prefix(table, parent, actual, expected), "guard-hook-order")


def plans(parsed, chains, hooks, migration_sha):
    try:
        validate_rules(parsed, chains, hooks)
        return {}
    except ValueError:
        pass
    snapshot = owned_snapshot(parsed)
    any_owned = any(x["chains"] or x["rules"] for x in snapshot.values())
    # Exact predecessor receipt must be approved. This covers profile changes
    # without treating an arbitrary unfamiliar current firewall as safe.
    need(not any_owned or (migration_sha is not None and digest(snapshot) == migration_sha),
         "unrecognized-firewall-predecessor")
    result = {}
    for table in ("filter", "mangle", "nat"):
        existing = {name for name in parsed[table]["chains"] if name.startswith(PREFIX)}
        target = set(chains[table])
        lines = ["*" + table]
        for name in sorted(target - existing):
            lines.append("-N " + name)
        for name in sorted(existing):
            lines.append("-F " + name)
        for parent, rules in parsed[table]["rules"].items():
            if parent.startswith(PREFIX):
                continue
            for rule in rules:
                if owned_rule(parent, rule):
                    lines.append(shlex.join(["-D", parent, *rule]))
        for name in sorted(existing - target):
            lines.append("-X " + name)
        for name, body in chains[table].items():
            for rule in body:
                lines.append(shlex.join(["-A", name, *rule]))
        for t, parent, rule in reversed(hooks):
            if t == table:
                lines.append(shlex.join(["-I", parent, "1", *rule]))
        lines.append("COMMIT")
        result[table] = "\n".join(lines) + "\n"
    return result


def spec(value):
    host = value["HostConfig"]
    config = value["Config"]
    mounts = []
    for mount in value["Mounts"]:
        if mount["Type"] == "tmpfs" and mount["Destination"] == "/tmp":
            continue
        mounts.append({k: mount[k] for k in ("Type", "Source", "Destination", "RW", "Propagation")})
    selected = {
        "user": config["User"], "command": config["Cmd"], "entrypoint": config.get("Entrypoint"),
        "host": {k: host.get(k) for k in (
            "NetworkMode", "ReadonlyRootfs", "Privileged", "CapAdd", "CapDrop", "SecurityOpt",
            "PidMode", "IpcMode", "UTSMode", "Devices", "DeviceRequests", "VolumesFrom",
            "PublishAllPorts", "RestartPolicy", "PidsLimit", "Memory", "NanoCpus",
            "Dns", "DnsSearch", "DnsOptions", "ExtraHosts", "Sysctls", "PortBindings", "Tmpfs")},
        "log_type": host["LogConfig"]["Type"], "log_option_count": value["LogOptionCount"],
        "mounts": sorted(mounts, key=lambda x: x["Destination"]),
    }
    if isinstance(selected["host"]["ExtraHosts"], list):
        selected["host"]["ExtraHosts"] = sorted(selected["host"]["ExtraHosts"])
    for binding in selected["host"]["PortBindings"].values():
        binding.sort(key=lambda x: (x["HostIp"], x["HostPort"]))
    return selected


def validate_mounts_resources(actual, shared):
    root = shared["runtime_root"]
    tls_root = root.rsplit("/", 1)[0] + "/tls"
    expected = [
        {"Type": "bind", "Source": root + "/secrets", "Destination": "/run/secrets", "RW": False, "Propagation": "rprivate"},
        {"Type": "bind", "Source": root + "/config", "Destination": "/run/config", "RW": False, "Propagation": "rprivate"},
        {"Type": "bind", "Source": tls_root, "Destination": "/run/tls", "RW": False, "Propagation": "rprivate"},
        {"Type": "bind", "Source": root + "/state", "Destination": "/state", "RW": True, "Propagation": "rprivate"},
        # Mount the directory so a broker restart may replace the socket inode.
        # No broker state, private key, root directory or Docker socket is shared.
        {"Type": "bind", "Source": "/run/reach-owner-mcp", "Destination": "/run/reach-owner-mcp", "RW": False, "Propagation": "rprivate"},
    ]
    need(actual["mounts"] == sorted(expected, key=lambda x: x["Destination"]), "mount-allowlist")
    h = actual["host"]
    need(h["PidsLimit"] == 96 and h["Memory"] == 402653184 and h["NanoCpus"] == 500000000, "resource-limits")
    need(isinstance(h["Tmpfs"], dict) and set(h["Tmpfs"]) == {"/tmp"}, "tmpfs-path")
    options = set(h["Tmpfs"]["/tmp"].split(","))
    options.discard("rw")  # Docker may omit the default rw token in inspect.
    need(options in ({"noexec", "nosuid", "size=16m"},
                     {"noexec", "nosuid", "size=16777216"}), "tmpfs-options")


def validate_network_attachment(value, network, shared, owner):
    """Check requested attachment before start; require effective binding while running."""
    name = shared["network"]["name"]
    need(value["HostConfig"]["NetworkMode"] == name, "network-mode")
    attachments = value["NetworkSettings"]["Networks"]
    need(set(attachments) == {name}, "network-count")
    attached = attachments[name]
    need(attached["IPAMConfig"] == {"IPv4Address": shared["network"]["container_ip"]},
         "network-intent")
    state = value["State"]
    need(not state["Paused"] and not state["Restarting"] and not state["Dead"], "container-state")
    if state["Running"]:
        need(attached["NetworkID"] == owner["network_id"]
             and re.fullmatch("[a-f0-9]{64}", attached["EndpointID"])
             and attached["IPAddress"] == shared["network"]["container_ip"]
             and attached["Gateway"] == shared["network"]["gateway"]
             and set(network["Containers"]) == {value["Id"]}, "running-network")
    else:
        # Docker create records the network name and requested IP but does not
        # allocate an endpoint or NetworkID until start. A stopped prior runtime
        # may retain the correct NetworkID; neither state is a live attachment.
        need(attached["NetworkID"] in ("", owner["network_id"])
             and attached["EndpointID"] == "" and attached["IPAddress"] == ""
             and attached["Gateway"] == "" and not network["Containers"], "stopped-network")


def validate_runtime(facts, shared, owner, chains, hooks, now):
    value = facts["container"]
    need(re.fullmatch("[a-f0-9]{64}", value["Id"]) and value["Name"] == "/" + owner["container_name"], "container-identity")
    need(value["Image"] == shared["image_id"] and value["Config"]["Hostname"] == value["Id"][:12], "image-hostname")
    need(value["ComposeProject"] == "reach-gateway" and value["ComposeService"] == "edge", "compose-identity")
    actual = spec(value)
    need(actual == owner["container_spec"] and digest(actual) == shared["container_spec_sha256"], "container-spec")
    need(actual["user"] == "10008:10008" and actual["command"] == ["python", "/app/service.py"]
         and actual["entrypoint"] in (None, []), "runtime-command")
    validate_mounts_resources(actual, shared)
    h = actual["host"]
    need(h["ReadonlyRootfs"] is True and h["Privileged"] is False and not h["CapAdd"]
         and h["CapDrop"] == ["ALL"] and h["SecurityOpt"] == ["no-new-privileges:true"]
         and h["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0}
         and actual["log_type"] == "none" and actual["log_option_count"] == 0, "runtime-isolation")
    need(not h["Devices"] and not h["DeviceRequests"] and not h["VolumesFrom"]
         and not h["PidMode"] and h["IpcMode"] == "private" and not h["UTSMode"]
         and h["PublishAllPorts"] is False, "runtime-namespaces")
    expected_ports = {"18885/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18885"}],
                      "19444/tcp": sorted([{"HostIp": x["address"], "HostPort": "19444"} for x in owner["binds"]],
                                         key=lambda x: (x["HostIp"], x["HostPort"]))}
    need(h["PortBindings"] == expected_ports, "private-bindings")
    need(h["Dns"] == owner["dns"] and h["DnsSearch"] == ["."]
         and h["DnsOptions"] == ["ndots:0", "timeout:2", "attempts:1"]
         and h["Sysctls"] == {"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}, "dns-ipv6")
    expected_hosts = sorted(name + ":" + ip for name, addresses in owner["github_hosts"].items() for ip in addresses)
    need(h["ExtraHosts"] == expected_hosts, "oauth-static-hosts")
    network = facts["network"]
    need(network["Id"] == owner["network_id"] and network["Name"] == shared["network"]["name"]
         and network["Driver"] == "bridge" and network["Scope"] == "local"
         and network["EnableIPv6"] is False and network["Internal"] is False
         and not network["Options"] and not network["Ingress"] and not network["ConfigOnly"], "network-identity")
    need(network["IPAM"]["Driver"] == "default" and network["IPAM"]["Config"] ==
         [{"Subnet": shared["network"]["subnet"], "Gateway": shared["network"]["gateway"]}], "network-ipam")
    validate_network_attachment(value, network, shared, owner)
    parsed = parse_rules(facts["iptables"])
    validate_rules(parsed, chains, hooks)
    need(facts["iptables_backend"].startswith("iptables v") and "(legacy)" in facts["iptables_backend"], "iptables-backend")
    need(facts["environment_matches_image"] is True, "container-environment")
    boot = dp.machine_identity(facts["boot_id"])
    for bind in owner["binds"]:
        addresses = facts["interfaces"].get(bind["interface"], [])
        need(bind["address"] in addresses, "binding-interface")
    need(shared["network"]["gateway"] in facts["interfaces"].get(owner["bridge"], []), "docker-bridge-address")
    return {"version": 1, "deployment_id": shared["deployment_id"], "policy_sha256": digest(shared),
            "checked_at": int(now), "host_boot_id": boot, "container_id": value["Id"],
            "image_id": value["Image"], "network_id": owner["network_id"],
            "container_hostname": value["Id"][:12], "container_spec_sha256": digest(actual),
            "shared_rules_sha256": shared_rules_digest(chains, hooks),
            "guards_restored": True, "image_verified": True, "network_verified": True,
            "container_spec_verified": True}


def proof(facts, shared, owner, selected, attestation, chains, hooks, now):
    dp.profile(selected, shared)
    need(selected["enabled"], "profile-disabled")
    checked = validate_runtime(facts, shared, owner, chains, hooks, now)
    need(facts["container"]["State"]["Running"] is True, "gateway-not-running")
    for key in ("host_boot_id", "container_id", "image_id", "network_id", "shared_rules_sha256", "container_spec_sha256"):
        need(checked[key] == attestation[key], "runtime-changed")
    connection = facts["connection"]
    need(connection["vm_id"] == selected["vm_id"] and connection["machine_uuid"] == selected["machine_uuid"]
         and connection["account_sid"] == selected["account_sid"] and connection["desktop_state"] == "ready"
         and 0 <= now - connection["last_seen"] <= 15, "connection-not-current")
    guest = facts["guest"]
    need(guest["machine_uuid"] == selected["machine_uuid"] and guest["account_sid"] == selected["account_sid"]
         and guest["connection_id"] == connection["connection_id"]
         and guest["gateway_epoch"] == connection["gateway_epoch"]
         and type(guest["checked_at"]) is int and 0 <= now - guest["checked_at"] <= 120
         and guest["policy_sha256"] == selected["guest_policy_sha256"]
         and guest["checker_sha256"] == facts["guest_checker_sha256"], "guest-observation-binding")
    # These are owner-originated diagnostic observations, not worker-supplied flags.
    need(guest["origin"] == "owner-fixed-diagnostic" and guest["tls"]["verified"] is True
         and guest["tls"]["ca_sha256"] == shared["tls"]["ca_sha256"]
         and guest["tls"]["url"] == selected["worker_url"]
         and guest["firewall_policy_preserved"] is True
         and guest["source_address"] in selected["source_addresses"], "guest-diagnostic")
    if selected["kind"] == "windows-tailnet":
        adapter = selected["adapter"]
        peers = [peer for peer in facts["tailscale_peers"] if peer["ID"] == adapter["node_id"]]
        need(len(peers) == 1 and peers[0]["PublicKey"] == adapter["node_key"] and peers[0]["Online"] is True
             and set(selected["source_addresses"]) <= set(peers[0]["TailscaleIPs"]), "tailnet-peer")
    else:
        libvirt = facts["libvirt"]
        adapter = selected["adapter"]
        need(libvirt["uuid"] == adapter["domain_uuid"] and libvirt["machine_uuid"] == selected["machine_uuid"]
             and libvirt["mapping_verified"] is True and libvirt["network"] == adapter["network_name"]
             and libvirt["filter"] == adapter["nwfilter_name"] and libvirt["mac"] == adapter["mac_address"]
             and libvirt["filter_sha256"] == adapter["nwfilter_sha256"]
             and libvirt["live_filter_rules_verified"] is True, "libvirt-boundary")
    probes = facts["probes"]
    need(probes["container_environment"] is True and probes["dns_udp"] is True
         and probes["dns_tcp"] is True and probes["oauth_https"] is True, "egress-positive-probes")
    need(set(probes["denied"]) == {"bridge", "lan_host", "tailnet_host", "other_container", "guest", "link_local", "other_public_https"}
         and all(value is True for value in probes["denied"].values()), "egress-negative-probes")
    need(probes["private_routes_public"] == 404 and probes["unauthenticated_mcp"] == 401
         and probes["oauth_metadata"] is True and facts["private_routes_not_public"] is True, "public-boundary")
    result = {"version": 3, "vm_id": selected["vm_id"], "machine_uuid": selected["machine_uuid"],
              "account_sid": selected["account_sid"], "connection_id": connection["connection_id"],
              "gateway_epoch": connection["gateway_epoch"], "checked_at": int(now),
              "policy_sha256": digest(shared), "profile_sha256": digest(selected),
              "runtime_sha256": digest(attestation), "host_boot_id": checked["host_boot_id"],
              "container_id": checked["container_id"], "network_id": checked["network_id"],
              "observation_id": facts["observation_id"]}
    dp.hex_id(result["observation_id"])
    for key in ("manifest_sha256", "transport_sha256", "checker_sha256"):
        result[key] = shared[key]
    result.update({flag: True for flag in dp.PROOF_FLAGS})
    return result


def enrollment_profile(shared, owner, data):
    """Owner operation turns installer preflight + observed boundary into data."""
    owner_config(owner, shared)
    request = data["request"]
    need(request["standard_account"] is True and request["profile_ready"] is True,
         "compatible-standard-windows-required")
    vm_id = dp.vm_identity(request["vm_id"])
    uuid = dp.machine_identity(request["machine_uuid"])
    sid = dp.sid_identity(request["account_sid"])
    endpoint = data["worker_url"]
    need(endpoint in shared["tls"]["private_urls"], "unapproved-origin")
    binding = next(x for x in owner["binds"] if x["url"] == endpoint)
    guest = data["guest"]
    need(guest["origin"] == "owner-fixed-diagnostic" and guest["machine_uuid"] == uuid
         and guest["account_sid"] == sid and guest["standard_account"] is True
         and type(guest["os_build"]) is int and guest["os_build"] >= 22000
         and guest["os_architecture"] == "64-bit"
         and guest["baseline_preserved"] is True, "guest-enrollment-observation")
    dp.sha(guest["policy_sha256"])
    if data["kind"] == "windows-tailnet":
        peer = data["peer"]
        need(peer["Online"] is True and peer["ID"] == data["peer_id"], "tailnet-enrollment-peer")
        source = guest["source_address"]
        need(source in peer["TailscaleIPs"] and re.fullmatch(r"tailscale[0-9]{1,6}", binding["interface"]),
             "tailnet-enrollment-source")
        adapter = {"node_id": peer["ID"], "node_key": peer["PublicKey"], "interface": binding["interface"]}
    elif data["kind"] == "libvirt-isolated":
        boundary = data["libvirt"]
        need(boundary["machine_uuid"] == uuid and boundary["mapping_verified"] is True
             and boundary["live_filter_rules_verified"] is True, "libvirt-enrollment-mapping")
        source = guest["source_address"]
        need(source == boundary["source_address"] and binding["interface"] == boundary["bridge"],
             "libvirt-enrollment-source")
        adapter = {"domain_uuid": boundary["uuid"], "network_name": boundary["network"],
                   "nwfilter_name": boundary["filter"], "nwfilter_sha256": boundary["filter_sha256"],
                   "mac_address": boundary["mac"]}
    else:
        raise ValueError("unsupported-transport-kind")
    selected = {"version": 1, "vm_id": vm_id, "machine_uuid": uuid, "account_sid": sid,
                "enabled": True, "kind": data["kind"], "worker_url": endpoint,
                "source_addresses": [source], "guest_policy_sha256": guest["policy_sha256"],
                "adapter": adapter}
    dp.profile(selected, shared)
    return selected



def main():
    raw = sys.stdin.buffer.read(4194305)
    need(len(raw) <= 4194304, "input-bound")
    data = json.loads(raw)
    shared, owner = data["policy"], data["owner"]
    chains, hooks = recipes(shared, owner, data["profiles"])
    mode = data["mode"]
    if mode == "plan":
        parsed = parse_rules(data["facts"]["iptables"])
        migration = owner["migration_owned_sha256"]
        if "previous_profiles" in data:
            old_chains, old_hooks = recipes(shared, owner, data["previous_profiles"])
            validate_rules(parsed, old_chains, old_hooks)
            migration = digest(owned_snapshot(parsed))
        result = {"plans": plans(parsed, chains, hooks, migration),
                  "unowned_sha256": unowned_digest(parsed),
                  "shared_rules_sha256": shared_rules_digest(chains, hooks)}
    elif mode == "runtime":
        result = validate_runtime(data["facts"], shared, owner, chains, hooks, time.time())
    elif mode == "proof":
        result = proof(data["facts"], shared, owner, data["profile"], data["runtime"],
                       chains, hooks, time.time())
    elif mode == "enroll-profile":
        result = enrollment_profile(shared, owner, data)
    elif mode == "describe":
        parsed = parse_rules(data["facts"]["iptables"])
        result = {"owned_sha256": digest(owned_snapshot(parsed)),
                  "unowned_sha256": unowned_digest(parsed),
                  "container_spec": spec(data["facts"]["container"])}
    else:
        raise ValueError("unknown-mode")
    print(json.dumps({"ok": True, "result": result}, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Validation reasons are fixed strings; never echo caller data.
        reason = str(exc) if isinstance(exc, ValueError) and re.fullmatch("[a-z0-9-]{1,80}", str(exc)) else "validation-failed"
        print(json.dumps({"ok": False, "reason": reason}, separators=(",", ":")))
        sys.exit(1)
