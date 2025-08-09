help:
	@echo "make clean - reset the project and remove auto-generated assets."
	@echo "make ruff - run the Ruff linter."
	@echo "make fix - run the Ruff linter and fix any issues it can."
	@echo "make test - run the test suite."
	@echo "make coverage - view a report on test coverage."
	@echo "make format_check - run the Ruff formatter to check for formatting issues."
	@echo "make format - run the Ruff formatter."
	@echo "make check - run all the checkers and tests."
	@echo "make stubgen - generate type stubs for the project."
	@echo "make dist - make a dist/wheel for the project."
	@echo "make publish-test - publish the project to PyPI test instance."
	@echo "make publish-live - publish the project to PyPI production."
	@echo "make docs - run sphinx to create project documentation.\n"

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf .eggs/
	find . -name '*.egg-info' -exec rm -rf {} +
	find . -name '*.egg' -exec rm -f {} +
	rm -rf .coverage
	rm -rf docs/_build
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +

ruff:
	ruff check

fix:
	ruff check --fix

test: clean
	py.test

coverage: clean
	py.test --cov-report term-missing --cov=uflash tests/

format:
	ruff format

format_check:
	ruff format --check

check: clean ruff format_check coverage

stubgen:
	stubgen -p uflash -o .

dist: check
	python -m build

publish-test: dist
	twine upload --repository testpypi dist/*

publish-live: dist
	twine upload dist/*

docs: clean
	$(MAKE) -C docs html
