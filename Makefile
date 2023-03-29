# Initializations
init: init_elat init_test

init_elat:
	pip install --user -r requirements.txt

init_test:
	pip install --user -r requirements_test.txt

# Source distribution
sdist:
	python setup.py sdist

# Build
build:
	python setup.py build

# Install
install:
	pip install --user .

# Uninstall
uninstall:
	pip uninstall ELAT

# Tests
test:
	python test.py

# Clean
clean:
	python setup.py clean
	rm -rdf MANIFEST build dist elat/__pycache__

# Misc
.PHONY: init init_elat init_test build test
