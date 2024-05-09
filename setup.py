from setuptools import setup, find_packages

setup(
    name='Genesys',
    version='2.3',
    packages=find_packages(),
    package_data={'': ['*.yaml']},
    author='Matheus Almeida Santos Mendonça',
    author_email='matheuzengenharia@gmail.com',
    description='Uma ferramenta para gerenciar aplicação do Archy, as APIs do Genesys Cloud',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Matheus-Sueth/Genesys.git',
    install_requires=[
        'python-dotenv',
        'PyYAML',
        'requests',
        'setuptools'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License'
    ],
)
