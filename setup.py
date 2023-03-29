from distutils.core import setup

setup(name='ELAT',
      version='1.0',
      description='ECDSA Lattice Attack Toolkit',
      author='Thore Tiemann',
      author_email='peterpappenburg@fantasymail.de',
      url='https://github.com/lamermoon/elat',
      license='MIT License',
      packages=['elat'],
      requires=['sage'],
      install_requires=['sagemath-standard>=9.0'],
      test_requires=['ecdsa']
     )
