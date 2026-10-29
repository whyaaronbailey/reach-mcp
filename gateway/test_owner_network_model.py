"""Synthetic owner-network model tests. No host commands or live evidence."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import yaml

import owner_network_model as model
from test_deployment_policy import fixture_policy, fixture_profile, TEST_TAILNET


def setup_policy():
    shared = fixture_policy()
    shared["tls"]["private_urls"] = ["https://192.0.2.1:19444", "https://reach.example.invalid:19444"]
    spec = {"synthetic_test_only": True}
    shared["container_spec_sha256"] = model.digest(spec)
    owner = {"version": 1, "container_name": "reach-gateway-edge-1",
             "network_id": "a" * 64, "bridge": "br-" + "a" * 12,
             "binds": [{"url": shared["tls"]["private_urls"][0], "address": "192.0.2.1", "interface": "virbr-reach0"},
                       {"url": shared["tls"]["private_urls"][1], "address": str(TEST_TAILNET[1]), "interface": "tailscale0"}],
             "dns": ["8.8.8.8"], "github_hosts": {"github.com": ["140.82.112.3"], "api.github.com": ["140.82.114.6"]},
             "container_spec": spec, "migration_owned_sha256": None}
    first = fixture_profile()
    first["worker_url"] = shared["tls"]["private_urls"][0]
    first.update(kind="libvirt-isolated", source_addresses=["192.0.2.10"],
                 adapter={"domain_uuid": first["machine_uuid"], "network_name": "reach-private-network",
                          "nwfilter_name": "test-guest-guard", "nwfilter_sha256": "7" * 64,
                          "mac_address": "02:00:00:00:00:03"})
    second = copy.deepcopy(first)
    second.update(vm_id="vm-second", machine_uuid="11111111-2222-4333-8444-555555555555",
                  worker_url=shared["tls"]["private_urls"][1], kind="windows-tailnet",
                  source_addresses=[str(TEST_TAILNET[2])],
                  adapter={"node_id": "testNode", "node_key": "nodekey:" + "b" * 64, "interface": "tailscale0"})
    return shared, owner, first, second


def text_rules(chains, hooks):
    lines = []
    for table in ("filter", "mangle", "nat"):
        lines.append("*" + table)
        parents = ["INPUT", "FORWARD"] if table == "filter" else ["PREROUTING"]
        for parent in parents:
            lines.append(":" + parent + " ACCEPT [0:0]")
        for chain in chains[table]:
            lines.append(":" + chain + " - [0:0]")
        for t, parent, rule in hooks:
            if t == table:
                lines.append("-A " + parent + " " + " ".join(rule))
        for parent in parents:
            lines.append("-A " + parent + " -m comment --comment unrelated-control -j RETURN")
        for name, body in chains[table].items():
            for rule in body:
                lines.append("-A " + name + " " + " ".join(rule))
        lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def attachment_fixture(running=False):
    """Synthetic IDs with the exact empty attachment shape observed after Docker create."""
    shared, owner, _, _ = setup_policy()
    name = shared["network"]["name"]
    value = {"Id": "c" * 64, "HostConfig": {"NetworkMode": name},
             "State": {"Running": running, "Paused": False, "Restarting": False, "Dead": False},
             "NetworkSettings": {"Networks": {name: {
                 "IPAMConfig": {"IPv4Address": shared["network"]["container_ip"]},
                 "NetworkID": owner["network_id"] if running else "",
                 "EndpointID": "e" * 64 if running else "",
                 "IPAddress": shared["network"]["container_ip"] if running else "",
                 "Gateway": shared["network"]["gateway"] if running else "",
                 "MacAddress": "02:00:00:00:00:01" if running else "", "IPPrefixLen": 29 if running else 0}}}}
    network = {"Containers": {value["Id"]: {}} if running else {}}
    return value, network, shared, owner


def mount_fixture():
    shared = setup_policy()[0]
    root = shared["runtime_root"]
    selected = {"mounts": sorted([
        {"Type": "bind", "Source": root + suffix, "Destination": dest, "RW": writable, "Propagation": "rprivate"}
        for suffix, dest, writable in (("/config", "/run/config", False), ("/secrets", "/run/secrets", False),
                                     ("/state", "/state", True))] +
        [{"Type": "bind", "Source": root.rsplit("/", 1)[0] + "/tls", "Destination": "/run/tls",
          "RW": False, "Propagation": "rprivate"},
         {"Type": "bind", "Source": "/run/reach-owner-mcp", "Destination": "/run/reach-owner-mcp",
          "RW": False, "Propagation": "rprivate"}], key=lambda x: x["Destination"]),
        "host": {"PidsLimit": 96, "Memory": 402653184, "NanoCpus": 500000000,
                 "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"}}}
    return selected, shared


class OwnerNetworkTests(unittest.TestCase):
    def test_exact_disjoint_broker_predecessor_preserves_rules(self):
        shared, owner, first, second = setup_policy()
        chains, hooks = model.recipes(shared, owner, [first, second])
        parsed = model.parse_rules(text_rules(chains, hooks))
        parsed["nat"]["rules"]["PREROUTING"].insert(0, model.BROKER_LOCAL_NAT_PREDECESSOR.copy())
        before = copy.deepcopy(parsed)
        model.validate_rules(parsed, chains, hooks)
        self.assertEqual(model.plans(parsed, chains, hooks, None), {})
        self.assertEqual(parsed, before)
        self.assertEqual(model.unowned_digest(parsed), model.unowned_digest(before))

    def test_changed_or_broad_broker_predecessors_are_rejected(self):
        shared, owner, first, second = setup_policy()
        chains, hooks = model.recipes(shared, owner, [first, second])
        original = model.BROKER_LOCAL_NAT_PREDECESSOR
        variants = []
        for token, replacement in (("192.0.2.10/32", "192.0.2.11/32"),
                                   ("192.0.2.1/32", (str(TEST_TAILNET[1]) + "/32")),
                                   ("virbr-reach0", "tailscale1"), ("tcp", "udp"),
                                   ("19443", "19444"), ("19443", "19443:19444"),
                                   ("ACCEPT", "RETURN"), ("ACCEPT", "OTHER_CHAIN"),
                                   ("reach-private-network-broker-local", "unknown")):
            changed = original.copy()
            changed[changed.index(token)] = replacement
            variants.append(changed)
        variants.extend([["!", *original], original + ["!"],
                         original[:10] + ["-m", "multiport", "--dports", "19443,19444"] + original[12:],
                         original[:6] + original[8:]])
        for bad in variants:
            parsed = model.parse_rules(text_rules(chains, hooks))
            parsed["nat"]["rules"]["PREROUTING"].insert(0, bad)
            with self.subTest(rule=bad), self.assertRaisesRegex(ValueError, "guard-hook-order"):
                model.validate_rules(parsed, chains, hooks)

    def test_broker_exception_does_not_allow_other_chains_or_prefixes(self):
        shared, owner, first, second = setup_policy()
        chains, hooks = model.recipes(shared, owner, [first, second])
        for table, parent in (("filter", "INPUT"), ("filter", "FORWARD"), ("mangle", "PREROUTING")):
            parsed = model.parse_rules(text_rules(chains, hooks))
            parsed[table]["rules"][parent].insert(0, model.BROKER_LOCAL_NAT_PREDECESSOR.copy())
            with self.subTest(table=table, parent=parent), self.assertRaisesRegex(ValueError, "guard-hook-order"):
                model.validate_rules(parsed, chains, hooks)
        for prefix in ([model.BROKER_LOCAL_NAT_PREDECESSOR.copy()] * 2,
                       [["-j", "ACCEPT"], model.BROKER_LOCAL_NAT_PREDECESSOR.copy()]):
            parsed = model.parse_rules(text_rules(chains, hooks))
            parsed["nat"]["rules"]["PREROUTING"][:0] = prefix
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, "guard-hook-order"):
                model.validate_rules(parsed, chains, hooks)
        parsed = model.parse_rules(text_rules(chains, hooks))
        parsed["nat"]["rules"]["PREROUTING"].insert(1, model.BROKER_LOCAL_NAT_PREDECESSOR.copy())
        with self.assertRaisesRegex(ValueError, "guard-hook-order"):
            model.validate_rules(parsed, chains, hooks)

    def test_broker_exception_requires_disjoint_reach_port_and_hook_order(self):
        shared, owner, first, second = setup_policy()
        chains, hooks = model.recipes(shared, owner, [first, second])
        wanted = [r for t, p, r in hooks if t == "nat" and p == "PREROUTING"]
        preceding = model.BROKER_LOCAL_NAT_PREDECESSOR.copy()
        overlapping = copy.deepcopy(wanted)
        overlapping[0][overlapping[0].index("--dport") + 1] = "19443"
        self.assertFalse(model.ordered_hook_prefix("nat", "PREROUTING", [preceding] + overlapping, overlapping))
        parsed = model.parse_rules(text_rules(chains, hooks))
        parsed["nat"]["rules"]["PREROUTING"][:2] = list(reversed(wanted))
        parsed["nat"]["rules"]["PREROUTING"].insert(0, preceding)
        with self.assertRaisesRegex(ValueError, "guard-hook-order"):
            model.validate_rules(parsed, chains, hooks)

    def test_created_network_intent_and_running_attachment_are_distinct(self):
        value, network, shared, owner = attachment_fixture()
        model.validate_network_attachment(value, network, shared, owner)
        value["NetworkSettings"]["Networks"][shared["network"]["name"]]["NetworkID"] = owner["network_id"]
        model.validate_network_attachment(value, network, shared, owner)
        value, network, shared, owner = attachment_fixture(running=True)
        model.validate_network_attachment(value, network, shared, owner)

    def test_created_network_intent_rejects_substitution_or_live_endpoint(self):
        for field, invalid in (("NetworkID", "f" * 64), ("EndpointID", "e" * 64),
                               ("IPAddress", "198.51.100.2"), ("Gateway", "198.51.100.1"),
                               ("IPAMConfig", {"IPv4Address": "198.51.100.3"})):
            value, network, shared, owner = attachment_fixture()
            value["NetworkSettings"]["Networks"][shared["network"]["name"]][field] = invalid
            with self.subTest(field=field), self.assertRaises(ValueError):
                model.validate_network_attachment(value, network, shared, owner)
        for category in ("network-mode", "other-attachment", "other-container"):
            value, network, shared, owner = attachment_fixture()
            if category == "network-mode":
                value["HostConfig"]["NetworkMode"] = "host"
            elif category == "other-attachment":
                value["NetworkSettings"]["Networks"]["other-network"] = {}
            else:
                network["Containers"]["f" * 64] = {}
            with self.subTest(category=category), self.assertRaises(ValueError):
                model.validate_network_attachment(value, network, shared, owner)

    def test_running_network_never_accepts_only_created_intent(self):
        for field, invalid in (("NetworkID", ""), ("NetworkID", "f" * 64),
                               ("EndpointID", ""), ("IPAddress", ""), ("Gateway", "")):
            value, network, shared, owner = attachment_fixture(running=True)
            value["NetworkSettings"]["Networks"][shared["network"]["name"]][field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                model.validate_network_attachment(value, network, shared, owner)
        value, network, shared, owner = attachment_fixture(running=True)
        network["Containers"] = {}
        with self.assertRaises(ValueError):
            model.validate_network_attachment(value, network, shared, owner)

    def test_tailnet_profile_uses_reviewed_observed_host_interface(self):
        shared, owner, first, second = setup_policy()
        owner["binds"][1]["interface"] = "tailscale1"
        with self.assertRaises(ValueError):
            model.recipes(shared, owner, [first, second])
        second["adapter"]["interface"] = "tailscale1"
        chains, _ = model.recipes(shared, owner, [first, second])
        rule = next(x for x in chains["mangle"]["HOME_AI_REACH_PRE"] if second["source_addresses"][0] + "/32" in x)
        self.assertEqual(rule[rule.index("-i") + 1], "tailscale1")
        for invalid in ("eth0", "tailscale", "tailscaleX", "tailscale1-extra"):
            bad_owner = copy.deepcopy(owner); bad_owner["binds"][1]["interface"] = invalid
            bad_profile = copy.deepcopy(second); bad_profile["adapter"]["interface"] = invalid
            with self.subTest(interface=invalid), self.assertRaises(Exception):
                model.recipes(shared, bad_owner, [first, bad_profile])

    def test_profiles_are_independent_and_shared_digest_stable(self):
        shared, owner, first, second = setup_policy()
        one, hooks = model.recipes(shared, owner, [first])
        two, hooks_two = model.recipes(shared, owner, [first, second])
        self.assertEqual(model.shared_rules_digest(one, hooks), model.shared_rules_digest(two, hooks_two))
        first_rules = [x for x in two["filter"]["HOME_AI_REACH_HOST"] if "home-ai-reach-vm-" + first["vm_id"] in x]
        self.assertEqual(first_rules, one["filter"]["HOME_AI_REACH_HOST"][:-1])
        self.assertEqual(first_rules[0][-1], "RETURN")  # preserve later host restrictions
        second["enabled"] = False
        revoked, _ = model.recipes(shared, owner, [first, second])
        self.assertEqual(revoked, one)

    def test_interface_and_destination_are_bound_to_profile(self):
        shared, owner, first, second = setup_policy()
        chains, _ = model.recipes(shared, owner, [first, second])
        rule = next(x for x in chains["mangle"]["HOME_AI_REACH_PRE"] if (str(TEST_TAILNET[2]) + "/32") in x)
        self.assertIn((str(TEST_TAILNET[1]) + "/32"), rule)
        self.assertIn("tailscale0", rule)
        self.assertNotIn("192.0.2.1/32", rule)
        second["worker_url"] = "https://unknown.example:19444"
        with self.assertRaises(Exception):
            model.recipes(shared, owner, [first, second])

    def test_exact_current_rules_need_no_mutation(self):
        shared, owner, first, _ = setup_policy()
        chains, hooks = model.recipes(shared, owner, [first])
        parsed = model.parse_rules(text_rules(chains, hooks))
        model.validate_rules(parsed, chains, hooks)
        self.assertEqual(model.plans(parsed, chains, hooks, None), {})

    def test_unknown_or_reordered_guard_refuses_without_approved_predecessor(self):
        shared, owner, first, _ = setup_policy()
        chains, hooks = model.recipes(shared, owner, [first])
        parsed = model.parse_rules(text_rules(chains, hooks))
        parsed["filter"]["rules"]["INPUT"].reverse()
        with self.assertRaises(ValueError):
            model.plans(parsed, chains, hooks, None)

    def test_atomic_plans_only_change_owned_chains(self):
        shared, owner, first, second = setup_policy()
        before, old_hooks = model.recipes(shared, owner, [first])
        target, hooks = model.recipes(shared, owner, [first, second])
        parsed = model.parse_rules(text_rules(before, old_hooks))
        predecessor = model.digest(model.owned_snapshot(parsed))
        plans = model.plans(parsed, target, hooks, predecessor)
        self.assertEqual(list(plans), ["filter", "mangle", "nat"])
        self.assertTrue(all(value.endswith("COMMIT\n") for value in plans.values()))
        for value in plans.values():
            for line in value.splitlines():
                if line.startswith(("-F ", "-X ", "-N ")):
                    self.assertTrue(line.split()[1].startswith(model.PREFIX))
            self.assertNotIn("unrelated-control", value)

    def test_guard_rule_content_and_extra_owned_rules_are_rejected(self):
        shared, owner, first, _ = setup_policy()
        chains, hooks = model.recipes(shared, owner, [first])
        parsed = model.parse_rules(text_rules(chains, hooks))
        parsed["filter"]["rules"]["HOME_AI_REACH_HOST"].insert(0, ["-j", "ACCEPT"])
        with self.assertRaises(ValueError):
            model.validate_rules(parsed, chains, hooks)

    def test_owner_spec_digest_and_ipv4_pins_are_required(self):
        shared, owner, first, _ = setup_policy()
        owner["github_hosts"]["github.com"] = ["127.0.0.1"]
        with self.assertRaises(ValueError):
            model.recipes(shared, owner, [first])
        shared, owner, first, _ = setup_policy()
        owner["container_spec"]["changed"] = True
        with self.assertRaises(ValueError):
            model.recipes(shared, owner, [first])

    def test_enrollment_is_data_only_and_checks_observed_stable_peer(self):
        shared, owner, first, _ = setup_policy()
        owner["binds"][1]["interface"] = "tailscale1"
        endpoint = shared["tls"]["private_urls"][1]
        data = {"kind": "windows-tailnet", "worker_url": endpoint, "peer_id": "testNode",
                "request": {"vm_id": "vm-third", "machine_uuid": first["machine_uuid"],
                            "account_sid": first["account_sid"], "standard_account": True, "profile_ready": True},
                "peer": {"ID": "testNode", "PublicKey": "nodekey:" + "9" * 64,
                         "Online": True, "TailscaleIPs": [str(TEST_TAILNET[3])]},
                "guest": {"origin": "owner-fixed-diagnostic",
                          "machine_uuid": first["machine_uuid"], "account_sid": first["account_sid"],
                          "source_address": str(TEST_TAILNET[3]), "policy_sha256": "f" * 64,
                          "standard_account": True, "os_build": 26100, "os_architecture": "64-bit", "baseline_preserved": True,
                          "tls": {"verified": True, "url": endpoint, "ca_sha256": shared["tls"]["ca_sha256"]}}}
        selected = model.enrollment_profile(shared, owner, data)
        self.assertEqual(selected["vm_id"], "vm-third")
        self.assertEqual(selected["adapter"]["node_id"], "testNode")
        self.assertEqual(selected["adapter"]["interface"], "tailscale1")
        for category, field, invalid in (("request", "standard_account", False),
                                          ("peer", "ID", "otherNode"),
                                          ("peer", "Online", False),
                                          ("guest", "source_address", str(TEST_TAILNET[99]))):
            bad = copy.deepcopy(data); bad[category][field] = invalid
            with self.subTest(category=category, field=field), self.assertRaises(ValueError):
                model.enrollment_profile(shared, owner, bad)

    def test_proof_rejects_stale_wrong_vm_or_self_reported_guest_evidence(self):
        shared, owner, _, selected = setup_policy()
        chains, hooks = model.recipes(shared, owner, [selected])
        attestation = {"host_boot_id": "a" * 8 + "-aaaa-4aaa-8aaa-" + "a" * 12,
                       "container_id": "1" * 64, "image_id": shared["image_id"], "network_id": owner["network_id"],
                       "shared_rules_sha256": model.shared_rules_digest(chains, hooks),
                       "container_spec_sha256": shared["container_spec_sha256"]}
        connection = {"vm_id": selected["vm_id"], "machine_uuid": selected["machine_uuid"],
                      "account_sid": selected["account_sid"], "desktop_state": "ready",
                      "last_seen": 1000, "connection_id": "2" * 32, "gateway_epoch": "3" * 32}
        guest = {"machine_uuid": selected["machine_uuid"], "account_sid": selected["account_sid"],
                 "connection_id": connection["connection_id"], "gateway_epoch": connection["gateway_epoch"],
                 "checked_at": 1000, "policy_sha256": selected["guest_policy_sha256"],
                 "checker_sha256": "4" * 64, "origin": "owner-fixed-diagnostic",
                 "tls": {"verified": True, "ca_sha256": shared["tls"]["ca_sha256"], "url": selected["worker_url"]},
                 "firewall_policy_preserved": True, "source_address": selected["source_addresses"][0]}
        facts = {"container": {"State": {"Running": True}}, "connection": connection, "guest": guest,
                 "guest_checker_sha256": "4" * 64, "observation_id": "5" * 32,
                 "tailscale_peers": [{"ID": selected["adapter"]["node_id"], "PublicKey": selected["adapter"]["node_key"],
                                      "Online": True, "TailscaleIPs": selected["source_addresses"]}],
                 "private_routes_not_public": True,
                 "probes": {"container_environment": True, "dns_udp": True, "dns_tcp": True, "oauth_https": True,
                            "denied": {x: True for x in ("bridge", "lan_host", "tailnet_host", "other_container",
                                                        "guest", "link_local", "other_public_https")},
                            "private_routes_public": 404, "unauthenticated_mcp": 401, "oauth_metadata": True}}
        with patch.object(model, "validate_runtime", return_value=attestation):
            good = model.proof(facts, shared, owner, selected, attestation, chains, hooks, 1000)
            self.assertTrue(all(good[x] is True for x in model.dp.PROOF_FLAGS))
            for field, invalid in (("origin", "worker-self-report"), ("checked_at", 879),
                                   ("account_sid", "S-1-5-21-1-2-3-9999"), ("connection_id", "9" * 32),
                                   ("firewall_policy_preserved", False), ("source_address", str(TEST_TAILNET[9999])), ("policy_sha256", "0" * 64)):
                bad = copy.deepcopy(facts); bad["guest"][field] = invalid
                with self.subTest(field=field), self.assertRaises(ValueError):
                    model.proof(bad, shared, owner, selected, attestation, chains, hooks, 1000)
            bad = copy.deepcopy(facts); bad["probes"]["denied"]["guest"] = False
            with self.assertRaises(ValueError):
                model.proof(bad, shared, owner, selected, attestation, chains, hooks, 1000)
            bad = copy.deepcopy(facts); bad["connection"]["desktop_state"] = "signed-out"
            with self.assertRaises(ValueError):
                model.proof(bad, shared, owner, selected, attestation, chains, hooks, 1000)

    def test_mount_and_resource_allowlist_rejects_host_socket_and_extra_shares(self):
        selected, shared = mount_fixture()
        model.validate_mounts_resources(selected, shared)
        for source in ("/var/run/docker.sock", "/", "/mnt/user"):
            bad = copy.deepcopy(selected); bad["mounts"][0]["Source"] = source
            with self.assertRaises(ValueError):
                model.validate_mounts_resources(bad, shared)
        bad = copy.deepcopy(selected); bad["mounts"][0]["RW"] = True
        with self.assertRaises(ValueError):
            model.validate_mounts_resources(bad, shared)
        bad = copy.deepcopy(selected); bad["host"]["Tmpfs"]["/tmp"] = "rw,size=16m"
        with self.assertRaises(ValueError):
            model.validate_mounts_resources(bad, shared)

    def test_owner_broker_directory_mount_cannot_be_omitted_replaced_or_writable(self):
        selected, shared = mount_fixture()
        model.validate_mounts_resources(selected, shared)
        index = next(i for i, mount in enumerate(selected["mounts"])
                     if mount["Destination"] == "/run/reach-owner-mcp")
        for field, invalid in (("Source", "/run/reach-owner-mcp/owner.sock"),
                               ("Source", "/var/lib/reach-owner"),
                               ("Destination", "/run/reach-owner-mcp/owner.sock"),
                               ("RW", True), ("Propagation", "rshared")):
            bad = copy.deepcopy(selected)
            bad["mounts"][index][field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                model.validate_mounts_resources(bad, shared)
        bad = copy.deepcopy(selected)
        del bad["mounts"][index]
        with self.assertRaises(ValueError):
            model.validate_mounts_resources(bad, shared)
        bad = copy.deepcopy(selected)
        bad["mounts"].append({"Type": "bind", "Source": "/var/run/docker.sock",
                              "Destination": "/var/run/docker.sock", "RW": False,
                              "Propagation": "rprivate"})
        with self.assertRaises(ValueError):
            model.validate_mounts_resources(bad, shared)

    def test_both_compose_candidates_keep_original_mounts_and_add_only_broker_directory(self):
        root = "/var/lib/reach/reach-gateway"
        expected = [root + "/runtime/secrets:/run/secrets:ro",
                    root + "/runtime/config:/run/config:ro",
                    root + "/tls:/run/tls:ro",
                    root + "/runtime/state:/state:rw",
                    "/run/reach-owner-mcp:/run/reach-owner-mcp:ro"]
        for name in ("compose.yaml", "compose.gateway.yaml"):
            with self.subTest(source=name):
                config = yaml.safe_load((Path(__file__).parent / 'fixtures' / name).read_text("utf-8"))
                self.assertEqual(config["services"]["edge"]["volumes"], expected)


if __name__ == "__main__":
    unittest.main()
