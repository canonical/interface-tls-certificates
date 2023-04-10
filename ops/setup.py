#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
from setuptools import setup, find_namespace_packages

setup(
    author="Charmed Kubernetes",
    author_email="k8s-crew@lists.canonical.com",
    description="TLS Certificate Interface for Charmed Operators",
    long_description=Path("README.md").read_text(),
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    license="MIT license",
    include_package_data=True,
    keywords=["juju", "charming", "certificates", "ops", "framework", "interface"],
    name="ops.interface_tls_certificates",
    packages=find_namespace_packages(include=["ops.*"]),
    url="https://github.com/juju-solutions/interface-tls-certificates/blob/HEAD/ops",
    version="0.1.0",
    zip_safe=True,
    install_requires=[
        "backports.cached-property",
        "pydantic",
        "ops",
    ],
)
