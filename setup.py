#!/usr/bin/env python3

from setuptools import setup
import os
import sys


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(
    name='showcert',
    version='0.0.2',
    packages=[],
    scripts=['bin/showcert'],

    install_requires=['patool','filetype','filelock','setuptools', 'requests'],

    url='https://github.com/yaroslaff/showcert',
    license='MIT',
    author='Yaroslav Polyakov',
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    author_email='yaroslaff@gmail.com',
    description='dump local/remote certificate info',
    python_requires='>=3',
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
