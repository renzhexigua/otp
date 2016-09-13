from setuptools import setup


setup(
    name='otp',
    version='0.0.1',
    license='MIT',
    description='Module for generating and validating HOTP and TOTP tokens',
    author='renzhexigua',
    author_email='renzhexigua@163.com',
    packages=['otp'],
    package_data={
        'otp': ['README.md', 'LICENSE']
    },
	py_modules=['test_otp'],
    install_requires=[],
)
