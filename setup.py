from setuptools import setup, find_packages

setup(
    name='eTainter',
    version='0.1.0',
    url='https://github.com/DependableSystemsLab/eTainter',
    packages=find_packages(),
    install_requires=[],
    scripts=[       
        'bin/analyzer.py'
    ],      
    python_requires='>=3.8',
    license='MIT',
    
)
