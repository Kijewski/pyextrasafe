all: build docs test


.DELETE_ON_ERROR:
.ONESHELL:
.PHONY: all build clean dists docs install sdist test


export ENV_DIR ?= env
export PYTHON ?= python3.11


clean:
	-rm -r -- "./build/"
	-rm -r -- "./dist/"
	-rm -r -- "./pyextrasafe.egg-info/"
	-rm -r -- "./src/pyextrasafe.egg-info/"
	-rm -r -- "./target/"


${ENV_DIR}/: requirements-dev.txt
	set -eu

	rm -r -- "./$${ENV_DIR}/" || true
	python3 -m virtualenv -p "$${PYTHON}" --download -- "./${ENV_DIR}/"

	. "./${ENV_DIR}/bin/activate"
	python3 -m pip install -U pip
	python3 -m pip install -U wheel setuptools
	python3 -m pip install -Ur requirements-dev.txt


install: | ${ENV_DIR}/
	set -eu
	. "./$${ENV_DIR}/bin/activate"
	python3 -m pip install .


build: | ${ENV_DIR}/
	set -eu
	. "./$${ENV_DIR}/bin/activate"
	python3 -m build


sdist: | ${ENV_DIR}/
	set -eu
	. "./$${ENV_DIR}/bin/activate"
	python3 -m build --sdist


docs: install | ${ENV_DIR}/
	set -eu

	rm -r -- "./dist/doctrees/" || true
	rm -r -- "./dist/html/" || true

	. "./$${ENV_DIR}/bin/activate"
	python3 -m sphinx -M html ./docs/ ./dist/ -W


test: install | ${ENV_DIR}/
	set -eu
	. "./$${ENV_DIR}/bin/activate"
	python3 hello-world.py


dists:
	${MAKE} PYTHON=python3.8 ENV_DIR=env3.8 build || true
	${MAKE} PYTHON=python3.9 ENV_DIR=env3.9 build || true
	${MAKE} PYTHON=python3.10 ENV_DIR=env3.10 build || true
	${MAKE} PYTHON=python3.11 ENV_DIR=env3.11 build || true
