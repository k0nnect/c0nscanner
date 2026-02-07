from setuptools import setup, find_packages

setup(
    name="c0nscanner",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "c0nscanner": ["payloads/*.txt"],
    },
    entry_points={
        "console_scripts": [
            "c0nscanner=c0nscanner.__main__:main",
        ],
    },
)
