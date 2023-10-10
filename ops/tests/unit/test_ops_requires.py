# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import unittest.mock as mock
from collections import defaultdict
from pathlib import Path

import pytest
import yaml
from ops.charm import RelationBrokenEvent, CharmBase
from ops.interface_tls_certificates import CertificatesRequires


@pytest.fixture(scope="function")
def certificates_requirer():
    mock_charm = mock.MagicMock(auto_spec=CharmBase)
    mock_charm.framework.model.unit.name = "test/0"
    yield CertificatesRequires(mock_charm)


@pytest.fixture(autouse=True)
def mock_ca_cert(tmpdir):
    ca_cert = Path(tmpdir) / "ca.crt"
    ca_cert.write_bytes(b"abcd")
    yield ca_cert


@pytest.fixture()
def relation_data():
    yield yaml.safe_load(Path("tests/data/tls_certificate_data.yaml").open())


@pytest.mark.parametrize(
    "event_type", [None, RelationBrokenEvent], ids=["unrelated", "dropped relation"]
)
def test_is_ready_no_relation(certificates_requirer, event_type):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.__bool__.return_value = event_type is not None
        relation.units = []
        event = mock.MagicMock(spec=event_type)
        event.relation = relation
        assert certificates_requirer.is_ready is False
        assert "Missing" in certificates_requirer.evaluate_relation(event)
        assert certificates_requirer.ca is None
        assert certificates_requirer.client_certs == []
        assert certificates_requirer.client_certs_map == {}
        assert certificates_requirer.server_certs == []
        assert certificates_requirer.server_certs_map == {}


def test_is_ready_invalid_data(certificates_requirer, relation_data):
    relation_data["ca"] = 123
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0"]
        relation.data = {"remote/0": relation_data}
        assert certificates_requirer.is_ready is False


def test_is_ready_success(certificates_requirer, relation_data):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0"]
        relation.data = {"remote/0": relation_data}
        assert certificates_requirer.is_ready is True
        assert certificates_requirer.ca.startswith("-----BEGIN CERTIFICATE")


def test_client_certs(certificates_requirer, relation_data, mock_ca_cert, tmpdir):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0"]
        relation.data = {"remote/0": relation_data}

        assert isinstance(certificates_requirer.client_certs, list)
        assert len(certificates_requirer.client_certs) == 1
        first = certificates_requirer.client_certs[0]
        assert first.cert_type == "client"
        assert first.common_name == "system:kube-apiserver"
        assert first.key and first.cert

        assert isinstance(certificates_requirer.client_certs_map, dict)
        assert len(certificates_requirer.client_certs_map) == 1
        first = certificates_requirer.client_certs_map["system:kube-apiserver"]
        assert first.cert_type == "client"
        assert first.common_name == "system:kube-apiserver"
        assert first.key and first.cert


def test_server_certs(certificates_requirer, relation_data):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0", certificates_requirer.model.unit]
        relation.data = {
            "remote/0": relation_data,
            certificates_requirer.model.unit: {"common_name": "system:kube-apiserver"},
        }

        assert isinstance(certificates_requirer.server_certs, list)
        assert len(certificates_requirer.server_certs) == 1
        first = certificates_requirer.server_certs[0]
        assert first.cert_type == "server"
        assert first.common_name == "system:kube-apiserver"
        assert first.key and first.cert

        assert isinstance(certificates_requirer.server_certs_map, dict)
        assert len(certificates_requirer.server_certs_map) == 1
        first = certificates_requirer.server_certs_map["system:kube-apiserver"]
        assert first.cert_type == "server"
        assert first.common_name == "system:kube-apiserver"
        assert first.key and first.cert


def test_send_unit_name_on_join(certificates_requirer: CertificatesRequires):
    event = mock.MagicMock()
    event.relation.data = defaultdict(defaultdict)
    certificates_requirer._joined(event)
    name = event.relation.data[certificates_requirer.model.unit]["unit_name"]
    assert name == "test_0"


def test_request_client_certs(certificates_requirer):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0", certificates_requirer.model.unit]
        relation.data = defaultdict(defaultdict)
        certificates_requirer.request_client_cert(
            "system:kube-apiserver", ["my.service"]
        )
        request = relation.data[certificates_requirer.model.unit][
            "client_cert_requests"
        ]
        assert json.loads(request) == {
            "system:kube-apiserver": {"sans": ["my.service"]}
        }


def test_request_single_server_cert(certificates_requirer):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0", certificates_requirer.model.unit]
        relation.data = defaultdict(defaultdict)
        certificates_requirer.request_server_cert(
            "system:kube-apiserver", ["my.service"], "cert-1"
        )

        first = (
            relation.data[certificates_requirer.model.unit]["common_name"],
            relation.data[certificates_requirer.model.unit]["sans"],
            relation.data[certificates_requirer.model.unit]["certificate_name"],
        )
        assert first == ("system:kube-apiserver", '["my.service"]', "cert-1")
        assert "cert_requests" not in relation.data[certificates_requirer.model.unit]


def test_request_server_certs(certificates_requirer):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0", certificates_requirer.model.unit]
        relation.data = defaultdict(defaultdict)
        certificates_requirer.request_server_cert(
            "system:kube-apiserver", ["my.api.service"], "cert-1"
        )
        certificates_requirer.request_server_cert(
            "system:kube-apiserver", ["my.api.service.changed"], "cert-1"
        )
        certificates_requirer.request_server_cert(
            "system:kube-controller", ["my.ctl.service"]
        )

        first = (
            relation.data[certificates_requirer.model.unit]["common_name"],
            relation.data[certificates_requirer.model.unit]["sans"],
            relation.data[certificates_requirer.model.unit]["certificate_name"],
        )
        assert first == (
            "system:kube-apiserver",
            '["my.api.service.changed"]',
            "cert-1",
        )
        remainder = json.loads(
            relation.data[certificates_requirer.model.unit]["cert_requests"]
        )
        assert remainder["system:kube-controller"] == {"sans": ["my.ctl.service"]}


def test_intermediate_certs(certificates_requirer, relation_data, mock_ca_cert, tmpdir):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0"]
        relation.data = {"remote/0": relation_data}

        assert isinstance(certificates_requirer.intermediate_certs, list)
        assert len(certificates_requirer.intermediate_certs) == 1
        first = certificates_requirer.intermediate_certs[0]
        assert first.cert_type == "intermediate"
        assert first.common_name == "127.0.0.1"
        assert first.key == "FAKEKEY"
        assert first.cert == "FAKECERT"

        assert isinstance(certificates_requirer.intermediate_certs_map, dict)
        assert len(certificates_requirer.intermediate_certs_map) == 1
        first = certificates_requirer.intermediate_certs_map["127.0.0.1"]
        assert first.cert_type == "intermediate"
        assert first.common_name == "127.0.0.1"
        assert first.key == "FAKEKEY"
        assert first.cert == "FAKECERT"


def test_request_intermediate_certs(certificates_requirer):
    with mock.patch.object(
        CertificatesRequires, "relation", new_callable=mock.PropertyMock
    ) as mock_prop:
        relation = mock_prop.return_value
        relation.units = ["remote/0", certificates_requirer.model.unit]
        relation.data = defaultdict(defaultdict)
        certificates_requirer.request_intermediate_cert("127.0.0.1", ["1.1.1.1"])
        request = relation.data[certificates_requirer.model.unit][
            "intermediate_cert_requests"
        ]
        assert json.loads(request) == {"127.0.0.1": {"sans": ["1.1.1.1"]}}
