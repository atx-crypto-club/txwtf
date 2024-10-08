#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging


__title__ = "txwtf"
from txwtf.version import version as __version__  # noqa: F401

__author__ = "Joe Rivera <j@jriv.us>"
__repo__ = "https://github.com/atx-crypto-club/txwtf"
__license__ = "Copyright Joe Rivera 2023"


IS_RELEASE = False


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
del logging, logger
