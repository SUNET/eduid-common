#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2018 SUNET
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import atexit
import logging
import random
import shutil
import subprocess
import tempfile
import time
from abc import ABCMeta, abstractmethod
from typing import Any, Sequence

from eduid_common.misc.timeutil import utc_now

logger = logging.getLogger(__name__)


class EduidTemporaryInstance(object, metaclass=ABCMeta):
    """Singleton to manage a temporary instance of something needed when testing.

    Use this for testing purpose only. The instance is automatically destroyed
    at the end of the program.
    """

    _instance = None

    def __init__(self, max_retry_seconds: int):
        self._conn = None
        self._tmpdir = tempfile.mkdtemp()
        self._port = random.randint(40000, 65535)
        self._logfile = f'/tmp/{self.__class__.__name__}-{self.port}.log'

        start_time = utc_now()
        self._process = subprocess.Popen(self.command, stdout=open(self._logfile, 'wb'), stderr=subprocess.STDOUT,)

        interval = 0.2
        count = 0
        while True:
            count += 1
            time.sleep(interval)

            # Call a function of the subclass of this ABC to see if the instance is operational yet
            _res = self.setup_conn()

            time_now = utc_now()
            delta = time_now - start_time
            age = delta.total_seconds()
            if _res:
                logger.info(f'{self} instance started after {age} seconds (attempt {count})')
                break
            if age > max_retry_seconds:
                logger.error(f'{self} instance failed to start after {age} seconds')
                logger.error(f'{self} instance output:\n{self.output}')
                raise RuntimeError(f'{self} instance failed to start after {age} seconds')
            logger.debug(f'{self} {self.port} OUTPUT:\n{self.output}')

    @classmethod
    def get_instance(cls, max_retry_seconds: int = 20):
        if cls._instance is None:
            cls._instance = cls(max_retry_seconds=max_retry_seconds)
            atexit.register(cls._instance.shutdown)
        return cls._instance

    @abstractmethod
    def setup_conn(self) -> bool:
        """
        Initialise and test a connection of the instance in self._conn.

        Return True on success.
        """
        raise NotImplemented('All subclasses of EduidTemporaryInstance must implement setup_conn')

    @property
    @abstractmethod
    def conn(self) -> Any:
        """ Return the initialised _conn instance. No default since it ought to be typed in the subclasses. """
        raise NotImplemented('All subclasses of EduidTemporaryInstance should implement the conn property')

    @property
    @abstractmethod
    def command(self) -> Sequence[str]:
        """ This is the shell command to start the temporary instance. """
        raise NotImplemented('All subclasses of EduidTemporaryInstance must implement the command property')

    @property
    def port(self) -> int:
        return self._port

    @property
    def tmpdir(self) -> str:
        return self._tmpdir

    @property
    def output(self) -> str:
        with open(self._logfile, 'r') as fd:
            _output = ''.join(fd.readlines())
        return _output

    def shutdown(self):
        logger.debug(f'{self} output at shutdown:\n{self.output}')
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
        shutil.rmtree(self._tmpdir, ignore_errors=True)
