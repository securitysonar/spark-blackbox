from setuptools import setup, find_packages

setup(
    name="spark-service-mesh",
    version="1.4.2",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "cryptography>=42.0.0",
        "pydantic>=2.7.0"
    ],
    author="DevOps Team",
    description="Internal service mesh communication library"
)
