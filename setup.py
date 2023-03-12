import os

from setuptools import find_packages, setup


def get_version():
    """
    Get version info from version module dict.
    """
    vi = {}
    vf = os.path.join("txwtf", "version.py")
    with open(vf, 'r') as mod:
        code = compile(mod.read(), "version.py", "exec")
        exec(code, vi)
    return vi


version = get_version()["version"]


setup(
    name="txwtf",
    version=version,
    author="Joe Rivera",
    author_email="t@tx.wtf",
    description="atx crypto club web application",
    packages=find_packages(),
    url="https://github.com/atx-crypto-club/txwtf",
    zip_safe=True,
    package_data={
        'txwtf': [
            'webapp/templates/*.html',
            'webapp/assets/*',
        ],
    },
    entry_points={
        "console_scripts": [
            "txwtf = txwtf.__main__:root"
        ]
    },
)
