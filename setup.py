import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='drf_auth_users',
    version='0.3',
    packages=find_packages(),
    include_package_data=True,
    license='BSD License',  # example license
    description='This app is wrapper around \'social_django\' app to create reusable user module',
    long_description=README,
    url='https://www.example.com/',
    author='Hiren Patel',
    author_email='hiren@auberginesolutions.com',
    classifiers=[
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 2.0',  # replace "X.Y" as appropriate
        'Intended Audience :: Developers'
    ],
)