from setuptools import setup, find_packages
import os


def read(*paths):
    """Build a file path from *paths* and return the contents."""
    with open(os.path.join(*paths), 'r') as f:
        return f.read()


setup(
    name='sark',
    version='7.4.1',
    packages=find_packages(exclude=['media', 'plugins']),
    install_requires=['networkx', 'wrapt'],
    url='https://github.com/tmr232/Sark',
    license='MIT',
    author='Tamir Bahar',
    author_email='',
    description='IDA Scripting Library',
    long_description=(read('README.rst')),
)
