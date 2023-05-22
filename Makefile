all: build docs


.DELETE_ON_ERROR:
.ONESHELL:
.PHONY: all build clean dists docs install sdist


ENV_DIR ?= env

ifeq ($(strip ${PYTHON}),)
  PREFERRED_PYTHON_VERSION ?= python3.11
  ${ENV_DIR}/: PYTHON:=$(shell readlink -e "$(shell which ${PREFERRED_PYTHON_VERSION} python3 | head -n1)")
endif


clean:
	-rm -r -- "./build/"
	-rm -r -- "./dist/"
	-rm -r -- "./pyextrasafe.egg-info/"
	-rm -r -- "./src/pyextrasafe.egg-info/"
	-rm -r -- "./target/"


${ENV_DIR}/: requirements-dev.txt
	set -eu

	rm -r -- "./${ENV_DIR}/" || true
	"${PYTHON}" -m virtualenv -p "${PYTHON}" --download -- "./${ENV_DIR}/"

	. "./${ENV_DIR}/bin/activate"
	python3 -m pip install -U pip
	python3 -m pip install -U wheel setuptools
	python3 -m pip install -Ur requirements-dev.txt


install: | ${ENV_DIR}/
	set -eu
	. "./${ENV_DIR}/bin/activate"
	python3 -m pip install .


build: | ${ENV_DIR}/
	set -eu
	. "./${ENV_DIR}/bin/activate"
	python3 -m build


sdist: | ${ENV_DIR}/
	set -eu
	. "./${ENV_DIR}/bin/activate"
	python3 -m build --sdist


docs: install | ${ENV_DIR}/
	set -eu

	rm -r -- "./dist/doctrees/" || true
	rm -r -- "./dist/html/" || true

	. "./${ENV_DIR}/bin/activate"
	python3 -m sphinx -M html ./docs/ ./dist/


dists:
	${MAKE} PREFERRED_PYTHON_VERSION=python3.11 ENV_DIR=env3.11 build || true
	${MAKE} PREFERRED_PYTHON_VERSION=python3.10 ENV_DIR=env3.10 build || true
	${MAKE} PREFERRED_PYTHON_VERSION=python3.9 ENV_DIR=env3.9 build || true
	${MAKE} PREFERRED_PYTHON_VERSION=python3.8 ENV_DIR=env3.8 build || true
	${MAKE} PREFERRED_PYTHON_VERSION=python3.7 ENV_DIR=env3.7 build || true
