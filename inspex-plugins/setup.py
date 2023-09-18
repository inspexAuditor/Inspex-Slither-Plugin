from setuptools import setup, find_packages

setup(
    name="slither-my-plugins",
    description="Custom plugins for Inspex auditors.",
    url="https://github.com/inspexAuditor/inspex-slither",
    author="Inspex",
    version="0.1",
    packages=find_packages(),
    python_requires=">=3.6",
    install_requires=["slither-analyzer>=0.1"],
    entry_points={
        "slither_analyzer.plugin": "slither my-plugin=slither_my_plugin:make_plugin",
    },
)
