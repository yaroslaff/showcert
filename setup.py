#!/usr/bin/env python3

from setuptools import setup
import os
import sys

from importlib.machinery import SourceFileLoader

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

def get_version(path):
    foo = SourceFileLoader(os.path.basename(path),"bin/showcert").load_module()
    return foo.version

setup(
    name='showcert',
    version=get_version('bin/showcert'),
    packages=[],
    scripts=['bin/showcert'],

    install_requires=['pyOpenSSL>=22.0.0', 'pem'],

    url='https://github.com/yaroslaff/showcert',
    license='MIT',
    author='Yaroslav Polyakov',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    author_email='yaroslaff@gmail.com',
    description='dump local/remote certificate info',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
         'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.4',
    ],
)
