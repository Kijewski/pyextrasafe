#!/usr/bin/env python3

from logging import getLogger, basicConfig, INFO
from threading import Thread

import pyextrasafe


logger = getLogger(__name__)

if __name__ == "__main__":
    basicConfig(level=INFO)

    try:
        thread = Thread(target=print, args=["Hello, world!"])
        thread.start()
        thread.join()
    except Exception as ex:
        raise Exception("Could not run Thread (should have been able!)") from ex

    pyextrasafe.SafetyContext().enable(
        pyextrasafe.BasicCapabilities(),
        pyextrasafe.SystemIO().allow_stdout().allow_stderr(),
    ).apply_to_all_threads()

    try:
        thread = Thread(target=print, args=["Hello, world!"])
        thread.start()
        thread.join()
    except Exception:
        logger.exception("Could not run Thread (that's good!)", exc_info=True)
    else:
        raise Exception("Should not have been able to run thread")
