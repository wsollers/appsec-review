from setuptools import Extension, setup

setup(
    ext_modules=[
        Extension("fastmod._fastmod", sources=["src/fastmod.c"]),
    ],
)
