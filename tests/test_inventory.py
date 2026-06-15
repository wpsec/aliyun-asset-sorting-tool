import io
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest import mock
import xml.etree.ElementTree as ET

from scripts import aliyun_asset_inventory as inventory


def raw_row(**overrides):
    base = {
        "subscription": "dev",
        "profile": "dev",
        "source": "resourcecenter",
        "account_id": "1234567890",
        "region_id": "cn-shanghai",
        "zone_id": "",
        "service_code": "vpc",
        "service": "vpc（专有网络）",
        "resource_type": "",
        "resource_type_name": "",
        "resource_id": "",
        "resource_name": "",
        "status": "Available",
        "resource_group_id": "",
        "create_time": "",
        "expire_time": "",
        "tags": "",
        "ip_addresses": "",
    }
    base.update(overrides)
    return base


class VerifyPermissionsTest(unittest.TestCase):
    def test_verify_permissions_timeout_is_counted_as_failure(self):
        args = SimpleNamespace(region=None, timeout=7)
        subscription = inventory.Subscription(profile="dev", label="dev")
        timeout_error = subprocess.TimeoutExpired(
            cmd=["aliyun", "resourcecenter", "SearchResources"],
            timeout=args.timeout,
        )

        with mock.patch.object(inventory, "run_aliyun", side_effect=timeout_error):
            captured = io.StringIO()
            with redirect_stdout(captured):
                failed = inventory.verify_permissions(args, subscription)

        self.assertEqual(len(inventory.VERIFY_CHECKS), failed)
        self.assertIn("执行超时", captured.getvalue())


class TopologyRenderingTest(unittest.TestCase):
    def test_build_topology_documents_renders_basic_vpc_relationships(self):
        raw_rows = [
            raw_row(
                resource_type="ACS::VPC::VPC",
                resource_type_name="专有网络",
                resource_id="vpc-1",
                resource_name="core-vpc",
            ),
            raw_row(
                resource_type="ACS::VPC::VSwitch",
                resource_type_name="交换机",
                resource_id="vsw-1",
                resource_name="app-vsw",
                zone_id="cn-shanghai-a",
            ),
        ]
        details = inventory.DetailedAssets(
            vpc_vswitches=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "zone_id": "cn-shanghai-a",
                    "vswitch_id": "vsw-1",
                    "resource_id": "vsw-1",
                    "resource_name": "app-vsw",
                    "status": "Available",
                    "vpc_id": "vpc-1",
                    "cidr_block": "10.0.1.0/24",
                    "available_ip_address_count": "250",
                    "creation_time": "",
                }
            ],
            ecs_instances=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "zone_id": "cn-shanghai-a",
                    "instance_id": "i-1",
                    "instance_name": "web-1",
                    "host_name": "web-1",
                    "status": "Running",
                    "instance_type": "ecs.g6.large",
                    "cpu": "2",
                    "memory_mb": "4096",
                    "os_name": "Linux",
                    "image_id": "img-1",
                    "vpc_id": "vpc-1",
                    "vswitch_id": "vsw-1",
                    "private_ip": "10.0.1.10",
                    "public_ip": "",
                    "eip": "",
                    "security_group_ids": "sg-1;sg-2",
                    "charge_type": "PostPaid",
                    "creation_time": "",
                    "expired_time": "",
                    "tags": "",
                }
            ],
            vpc_eips=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "allocation_id": "eip-1",
                    "resource_id": "eip-1",
                    "resource_name": "public-web",
                    "ip_address": "1.1.1.1",
                    "status": "InUse",
                    "instance_id": "i-1",
                    "associated_instance_id": "",
                    "bind_resource_id": "",
                    "instance_type": "EcsInstance",
                    "bandwidth": "5",
                    "charge_type": "PayByTraffic",
                    "creation_time": "",
                }
            ],
        )

        docs = inventory.build_topology_documents(raw_rows, details)
        content = docs["cn-shanghai__vpc-1.md"]

        self.assertIn("subgraph subgraph_vsw_1", content)
        self.assertIn("ecs_cn_shanghai_i_1", content)
        self.assertIn("eip_cn_shanghai_eip_1 --> ecs_cn_shanghai_i_1", content)
        self.assertIn("安全组: sg-1,sg-2", content)

    def test_build_topology_documents_renders_alb_chain_without_guessing(self):
        raw_rows = [
            raw_row(
                resource_type="ACS::VPC::VPC",
                resource_type_name="专有网络",
                resource_id="vpc-1",
                resource_name="core-vpc",
            ),
            raw_row(
                resource_type="ACS::VPC::VSwitch",
                resource_type_name="交换机",
                resource_id="vsw-1",
                resource_name="app-vsw",
            ),
        ]
        details = inventory.DetailedAssets(
            vpc_vswitches=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "zone_id": "cn-shanghai-a",
                    "vswitch_id": "vsw-1",
                    "resource_id": "vsw-1",
                    "resource_name": "app-vsw",
                    "status": "Available",
                    "vpc_id": "vpc-1",
                    "cidr_block": "10.0.1.0/24",
                    "available_ip_address_count": "250",
                    "creation_time": "",
                }
            ],
            ecs_instances=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "zone_id": "cn-shanghai-a",
                    "instance_id": "i-backend",
                    "instance_name": "backend-1",
                    "host_name": "backend-1",
                    "status": "Running",
                    "instance_type": "ecs.g6.large",
                    "cpu": "2",
                    "memory_mb": "4096",
                    "os_name": "Linux",
                    "image_id": "img-1",
                    "vpc_id": "vpc-1",
                    "vswitch_id": "vsw-1",
                    "private_ip": "10.0.1.20",
                    "public_ip": "",
                    "eip": "",
                    "security_group_ids": "",
                    "charge_type": "PostPaid",
                    "creation_time": "",
                    "expired_time": "",
                    "tags": "",
                }
            ],
            alb_load_balancers=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "load_balancer_id": "alb-1",
                    "resource_id": "alb-1",
                    "load_balancer_name": "alb-main",
                    "resource_name": "alb-main",
                    "status": "Active",
                    "address": "alb.example.com",
                    "address_type": "Internet",
                    "vpc_id": "vpc-1",
                    "creation_time": "",
                    "tags": "",
                    "resource_group_id": "",
                }
            ],
            alb_server_groups=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "server_group_id": "sg-1",
                    "resource_id": "sg-1",
                    "server_group_name": "app-sg",
                    "resource_name": "app-sg",
                    "server_group_type": "Instance",
                    "protocol": "HTTP",
                    "vpc_id": "vpc-1",
                    "load_balancer_id": "alb-1",
                }
            ],
            alb_listeners=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "listener_id": "lsn-1",
                    "resource_id": "lsn-1",
                    "load_balancer_id": "alb-1",
                    "protocol": "HTTP",
                    "port": "80",
                    "status": "Running",
                    "server_group_ids": "sg-1",
                },
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "listener_id": "lsn-2",
                    "resource_id": "lsn-2",
                    "load_balancer_id": "alb-1",
                    "protocol": "HTTPS",
                    "port": "443",
                    "status": "Running",
                    "server_group_ids": "",
                },
            ],
            alb_server_group_servers=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "server_group_id": "sg-1",
                    "server_id": "i-backend",
                    "resource_id": "i-backend",
                    "status": "Available",
                    "port": "8080",
                }
            ],
        )

        docs = inventory.build_topology_documents(raw_rows, details)
        content = docs["cn-shanghai__vpc-1.md"]

        self.assertIn(
            "listener_alb_cn_shanghai_lsn_1 --> sgroup_alb_cn_shanghai_sg_1",
            content,
        )
        self.assertIn(
            "sgroup_alb_cn_shanghai_sg_1 --> ecs_cn_shanghai_i_backend",
            content,
        )
        self.assertNotIn(
            "listener_alb_cn_shanghai_lsn_2 --> sgroup_alb_cn_shanghai_sg_1",
            content,
        )

    def test_build_topology_documents_puts_unassigned_database_into_unassigned(self):
        raw_rows = [
            raw_row(
                resource_type="ACS::VPC::VPC",
                resource_type_name="专有网络",
                resource_id="vpc-1",
                resource_name="core-vpc",
            )
        ]
        details = inventory.DetailedAssets(
            rds_instances=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "instance_id": "rm-1",
                    "resource_id": "rm-1",
                    "resource_name": "reporting-db",
                    "status": "Running",
                    "engine": "MySQL",
                    "engine_version": "8.0",
                    "connection_mode": "Standard",
                    "charge_type": "PostPaid",
                    "vpc_id": "",
                    "vswitch_id": "",
                    "tags": "",
                    "resource_group_id": "",
                }
            ]
        )

        docs = inventory.build_topology_documents(raw_rows, details)

        self.assertIn("rm-1", docs["unassigned.md"])
        self.assertNotIn("rm-1", docs["cn-shanghai__vpc-1.md"])

    def test_build_topology_documents_marks_partial_relationships(self):
        raw_rows = [
            raw_row(
                resource_type="ACS::VPC::VPC",
                resource_type_name="专有网络",
                resource_id="vpc-1",
                resource_name="core-vpc",
            )
        ]
        details = inventory.DetailedAssets(
            collection_events=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "service": "vpc（专有网络）",
                    "api": "DescribeVSwitches",
                    "resource_id": "",
                    "status": "query_failed",
                    "message": "权限不足",
                }
            ]
        )

        docs = inventory.build_topology_documents(raw_rows, details)
        content = docs["cn-shanghai__vpc-1.md"]

        self.assertIn("检测到部分关系缺失", content)
        self.assertIn("DescribeVSwitches", content)
        self.assertIn("权限不足", content)

    def test_build_topology_drawio_documents_renders_basic_vpc_relationships(self):
        raw_rows = [
            raw_row(
                resource_type="ACS::VPC::VPC",
                resource_type_name="专有网络",
                resource_id="vpc-1",
                resource_name="core-vpc",
            ),
            raw_row(
                resource_type="ACS::VPC::VSwitch",
                resource_type_name="交换机",
                resource_id="vsw-1",
                resource_name="app-vsw",
                zone_id="cn-shanghai-a",
            ),
        ]
        details = inventory.DetailedAssets(
            vpc_vswitches=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "zone_id": "cn-shanghai-a",
                    "vswitch_id": "vsw-1",
                    "resource_id": "vsw-1",
                    "resource_name": "app-vsw",
                    "status": "Available",
                    "vpc_id": "vpc-1",
                    "cidr_block": "10.0.1.0/24",
                    "available_ip_address_count": "250",
                    "creation_time": "",
                }
            ],
            ecs_instances=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "zone_id": "cn-shanghai-a",
                    "instance_id": "i-1",
                    "instance_name": "web-1",
                    "host_name": "web-1",
                    "status": "Running",
                    "instance_type": "ecs.g6.large",
                    "cpu": "2",
                    "memory_mb": "4096",
                    "os_name": "Linux",
                    "image_id": "img-1",
                    "vpc_id": "vpc-1",
                    "vswitch_id": "vsw-1",
                    "private_ip": "10.0.1.10",
                    "public_ip": "",
                    "eip": "",
                    "security_group_ids": "sg-1;sg-2",
                    "charge_type": "PostPaid",
                    "creation_time": "",
                    "expired_time": "",
                    "tags": "",
                }
            ],
            vpc_eips=[
                {
                    "subscription": "dev",
                    "account_id": "1234567890",
                    "region_id": "cn-shanghai",
                    "allocation_id": "eip-1",
                    "resource_id": "eip-1",
                    "resource_name": "public-web",
                    "ip_address": "1.1.1.1",
                    "status": "InUse",
                    "instance_id": "i-1",
                    "associated_instance_id": "",
                    "bind_resource_id": "",
                    "instance_type": "EcsInstance",
                    "bandwidth": "5",
                    "charge_type": "PayByTraffic",
                    "creation_time": "",
                }
            ],
        )

        docs = inventory.build_topology_drawio_documents(raw_rows, details)
        xml_text = docs["cn-shanghai__vpc-1.drawio"]
        root = ET.fromstring(xml_text)
        diagram = root.find("diagram")
        self.assertIsNotNone(diagram)
        model = diagram.find("mxGraphModel")
        self.assertIsNotNone(model)
        cells = model.findall("./root/mxCell")

        self.assertIn("topology-drawio", docs["README.md"])
        self.assertIn("unassigned.drawio", docs["README.md"])
        self.assertTrue(any("core-vpc" in cell.attrib.get("value", "") for cell in cells))
        self.assertTrue(any("web-1" in cell.attrib.get("value", "") for cell in cells))
        self.assertTrue(any("eip-1" in cell.attrib.get("value", "") for cell in cells))
        self.assertTrue(any("image=data:image/svg+xml;base64" in cell.attrib.get("style", "") for cell in cells))

        ecs_cell = next(cell for cell in cells if "web-1" in cell.attrib.get("value", ""))
        eip_cell = next(cell for cell in cells if "eip-1" in cell.attrib.get("value", ""))
        edges = [cell for cell in cells if cell.attrib.get("edge") == "1"]
        self.assertTrue(
            any(
                edge.attrib.get("source") == eip_cell.attrib.get("id")
                and edge.attrib.get("target") == ecs_cell.attrib.get("id")
                for edge in edges
            )
        )


class MainValidationTest(unittest.TestCase):
    def test_parse_args_enables_topology_by_default(self):
        with mock.patch("sys.argv", ["aliyun_asset_inventory.py"]):
            args = inventory.parse_args()

        self.assertTrue(args.topology)

    def test_parse_args_enables_drawio_flag(self):
        with mock.patch("sys.argv", ["aliyun_asset_inventory.py", "--drawio"]):
            args = inventory.parse_args()

        self.assertTrue(args.drawio)

    def test_main_rejects_topology_with_no_detail(self):
        args = SimpleNamespace(
            no_checks=True,
            verify_only=False,
            checks_config="",
            severity_threshold="low",
            output="",
            report_output="",
            findings_output="",
            no_raw_csv=False,
            no_report=False,
            topology=True,
            no_detail=True,
            checks_only=False,
        )

        with mock.patch.object(inventory, "parse_args", return_value=args), mock.patch.object(
            inventory,
            "collect_subscriptions",
            return_value=[inventory.Subscription(profile="dev", label="dev")],
        ):
            captured = io.StringIO()
            with redirect_stderr(captured):
                code = inventory.main()

        self.assertEqual(2, code)
        self.assertIn("默认启用拓扑，--no-detail 需要配合 --no-topology 使用", captured.getvalue())

    def test_main_rejects_drawio_with_no_detail(self):
        args = SimpleNamespace(
            no_checks=True,
            verify_only=False,
            checks_config="",
            severity_threshold="low",
            output="",
            report_output="",
            findings_output="",
            no_raw_csv=False,
            no_report=False,
            topology=False,
            drawio=True,
            no_detail=True,
            checks_only=False,
        )

        with mock.patch.object(inventory, "parse_args", return_value=args), mock.patch.object(
            inventory,
            "collect_subscriptions",
            return_value=[inventory.Subscription(profile="dev", label="dev")],
        ):
            captured = io.StringIO()
            with redirect_stderr(captured):
                code = inventory.main()

        self.assertEqual(2, code)
        self.assertIn("--drawio 需要详情采集，不能与 --no-detail 同时使用", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
