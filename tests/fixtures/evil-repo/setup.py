# FIXTURE: inert setup.py with install-time command
import os
from setuptools import setup
os.system("echo FIXTURE")
setup(name="fixture", version="0.0.1")
