#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import argparse
import enum
import errno
import os
import sys
import logging
import select
import time
import uuid
import setproctitle
import signal
import contextlib
import pwd
import grp
import bsd
from threading import Thread, Condition, Timer, RLock
from freenas.dispatcher.rpc import RpcContext, RpcService, RpcException, generator
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.server import Server
from freenas.utils import configure_logging, first_or_default, query as q
from freenas.utils.trace_logger import TRACE


DEFAULT_SOCKET_ADDRESS = 'unix:///var/run/serviced.sock'
MAX_EVENTS = 16


class JobState(enum.Enum):
    UNKNOWN = 'UNKNOWN'
    STOPPED = 'STOPPED'
    RUNNING = 'RUNNING'
    DYING = 'DYING'


class Job(object):
    def __init__(self, context):
        self.context = context
        self.anonymous = False
        self.logger = None
        self.id = None
        self.label = None
        self.parent = None
        self.provides = set()
        self.requires = set()
        self.state = JobState.UNKNOWN
        self.program = None
        self.program_arguments = []
        self.pid = None
        self.sid = None
        self.plist = None
        self.started_at = None
        self.exited_at = None
        self.keep_alive = False
        self.throttle_interval = 0
        self.exit_timeout = 10
        self.stdout_fd = self.context.devnull
        self.stdout_path = None
        self.stderr_fd = self.context.devnull
        self.stderr_path = None
        self.run_at_load = False
        self.user = None
        self.group = None
        self.umask = None
        self.last_exit_code = None
        self.did_exec = False
        self.environment = {}
        self.respawns = 0
        self.cv = Condition()

    @property
    def children(self):
        return (j for j in self.context.jobs if j.parent is self)

    def load(self, plist):
        self.id = plist.get('ID', str(uuid.uuid4()))
        self.label = plist.get('Label')
        self.program = plist.get('Program')
        self.requires = set(plist.get('Requires', []))
        self.provides = set(plist.get('Provides', []))
        self.program_arguments = plist.get('ProgramArguments', [])
        self.stdout_path = plist.get('StandardOutPath')
        self.stderr_path = plist.get('StandardErrorPath')
        self.run_at_load = bool(plist.get('RunAtLoad', False))
        self.keep_alive = bool(plist.get('KeepAlive', False))
        self.throttle_interval = int(plist.get('ThrottleInterval', 0))
        self.environment = plist.get('EnvironmentVariables', {})
        self.user = plist.get('UserName')
        self.group = plist.get('GroupName')
        self.umask = plist.get('Umask')
        self.logger = logging.getLogger('Job:{0}'.format(self.label))

        if first_or_default(lambda j: j.label == self.label, self.context.jobs.values()):
            raise RpcException(errno.EEXIST, 'Job with label {0} already exists'.format(self.label))

        if not self.program:
            self.program = self.program_arguments[0]

        if self.stdout_path:
            self.stdout_fd = os.open(self.stdout_path, os.O_WRONLY | os.O_APPEND)

        if self.stderr_path:
            self.stderr_fd = os.open(self.stderr_path, os.O_WRONLY | os.O_APPEND)

        if self.run_at_load:
            self.start()

    def load_anonymous(self, parent, pid):
        try:
            proc = bsd.kinfo_getproc(pid)
            command = proc.command
        except LookupError:
            # Exited too quickly, but let's add it anyway - it will be removed in next event
            command = 'unknown'

        with self.cv:
            self.parent = parent
            self.id = str(uuid.uuid4())
            self.pid = pid
            self.label = 'anonymous.{0}@{1}'.format(command, self.pid)
            self.logger = logging.getLogger('Job:{0}'.format(self.label))
            self.anonymous = True
            self.state = JobState.RUNNING
            self.cv.notify_all()

    def unload(self):
        del self.context.jobs[self.id]

    def start(self):
        if not self.requires <= self.context.provides:
            return

        self.logger.info('Starting job')
        pid = os.fork()
        if pid == 0:
            os.kill(os.getpid(), signal.SIGSTOP)
            os.dup2(sys.stdout.fileno(), self.stdout_fd)
            os.dup2(sys.stderr.fileno(), self.stderr_fd)

            if self.user:
                user = pwd.getpwnam(self.user)
                os.setuid(user.pw_uid)

            if self.user:
                group = grp.getgrnam(self.group)
                os.setgid(group.gr_gid)

            bsd.closefrom(3)
            os.setsid()
            os.execvpe(self.program, self.program_arguments, self.environment)

        self.logger.debug('Started as PID {0}'.format(pid))
        self.pid = pid
        self.context.track_pid(self.pid)
        os.waitpid(self.pid, os.WUNTRACED)
        os.kill(self.pid, signal.SIGCONT)

    def stop(self):
        self.logger.info('Stopping job')
        self.did_exec = False
        self.state = JobState.DYING
        with self.cv:
            if self.state == JobState.STOPPED:
                return

            try:
                os.kill(self.pid, signal.SIGTERM)
            except ProcessLookupError:
                # Already dead
                with self.cv:
                    self.state = JobState.STOPPED
                    self.notify()

            if not self.cv.wait_for(lambda: self.state == JobState.STOPPED, self.exit_timeout):
                os.kill(self.pid, signal.SIGKILL)

            if not self.cv.wait_for(lambda: self.state == JobState.STOPPED, self.exit_timeout):
                self.logger.error('Unkillable process {0}'.format(self.pid))

    def pid_event(self, ev):
        if ev.fflags & select.KQ_NOTE_EXEC:
            try:
                proc = bsd.kinfo_getproc(self.pid)
            except LookupError:
                # Exited too quickly, exit info will be catched in another event
                return

            argv = list(proc.argv)
            self.logger.debug('Job did exec() into {0}'.format(argv))
            if argv == self.program_arguments and not self.did_exec:
                with self.cv:
                    try:
                        self.sid = os.getsid(self.pid)
                    except ProcessLookupError:
                        # Exited too quickly after exec()
                        return

                    self.did_exec = True
                    self.state = JobState.RUNNING
                    self.cv.notify_all()
                    self.context.provide(self.provides)

        if ev.fflags & select.KQ_NOTE_FORK:
            self.logger.debug('Job has forked')

        if ev.fflags & select.KQ_NOTE_EXIT:
            if not self.parent:
                # We need to reap direct children
                try:
                    os.waitpid(self.pid, 0)
                except BaseException as err:
                    self.logger.debug('waitpid() error: {0}'.format(err))

            with self.cv:
                self.logger.info('Job has exited with code {0}'.format(ev.data))
                self.pid = None
                self.state = JobState.STOPPED
                self.last_exit_code = ev.data

                if self.anonymous:
                    del self.context.jobs[self.id]

                self.cv.notify_all()

    def notify(self):
        pass

    def __getstate__(self):
        ret = {
            'ID': self.id,
            'ParentID': self.parent.id if self.parent else None,
            'Label': self.label,
            'Program': self.program,
            'ProgramArguments': self.program_arguments,
            'Provides': list(self.provides),
            'Requires': list(self.requires),
            'RunAtLoad': self.run_at_load,
            'KeepAlive': self.keep_alive,
            'State': self.state.name,
            'LastExitStatus': self.last_exit_code,
            'PID': self.pid
        }

        if self.stdout_path:
            ret['StandardOutPath'] = self.stdout_path

        if self.stdout_path:
            ret['StandardErrorPath'] = self.stderr_path

        if self.environment:
            ret['EnvironmentVariables'] = self.environment

        return ret


class ManagementService(RpcService):
    def __init__(self, context):
        self.context = context


class ControlService(RpcService):
    def __init__(self, context):
        self.context = context

    @generator
    def query(self, filter=None, params=None):
        return q.query(self.context.jobs.values(), *(filter or []), **(params or {}))

    def load(self, plist):
        with self.context.lock:
            job = Job(self.context)
            job.load(plist)
            self.context.jobs[job.id] = job

    def unload(self, name_or_id):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

            job.stop()
            job.unload()

    def start(self, name_or_id):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

        job.start()

    def stop(self, name_or_id):
        with self.context.lock:
            job = first_or_default(lambda j: j.label == name_or_id or j.id == name_or_id, self.context.jobs.values())
            if not job:
                raise RpcException(errno.ENOENT, 'Job {0} not found'.format(name_or_id))

            job.stop()


class Context(object):
    def __init__(self):
        self.server = None
        self.client = None
        self.jobs = {}
        self.provides = set()
        self.lock = RLock()
        self.kq = select.kqueue()
        self.devnull = os.open('/dev/null', os.O_RDWR)
        self.logger = logging.getLogger('Context')
        self.rpc = RpcContext()
        self.rpc.register_service_instance('serviced.management', ManagementService(self))
        self.rpc.register_service_instance('serviced.control', ControlService(self))

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def init_server(self, address):
        self.server = Server(self)
        self.server.rpc = self.rpc
        self.server.streaming = True
        self.server.start(address, transport_options={'permissions': 0o777})
        thread = Thread(target=self.server.serve_forever)
        thread.name = 'ServerThread'
        thread.daemon = True
        thread.start()

    def provide(self, targets):
        def doit():
            self.logger.debug('Adding dependency targets: {0}'.format(', '.join(targets)))
            with self.lock:
                self.provides |= targets
                for job in self.jobs.values():
                    if job.state == JobState.STOPPED and job.requires <= self.provides:
                        job.start()

        Timer(2, doit).start()

    def job_by_pid(self, pid):
        job = first_or_default(lambda j: j.pid == pid, self.jobs.values())
        return job

    def event_loop(self):
        while True:
            with contextlib.suppress(InterruptedError):
                for ev in self.kq.control(None, MAX_EVENTS):
                    self.logger.log(TRACE, 'New event: {0}'.format(ev))
                    if ev.filter == select.KQ_FILTER_PROC:
                        job = self.job_by_pid(ev.ident)
                        if job:
                            job.pid_event(ev)
                            continue

                        if ev.fflags & select.KQ_NOTE_CHILD:
                            self.logger.info('New child process {0}, parent {1}'.format(ev.ident, ev.data))
                            pjob = self.job_by_pid(ev.data)
                            if not pjob:
                                self.untrack_pid(ev.ident)
                                continue

                            # Stop tracking at session ID boundary
                            try:
                                if pjob.sid != os.getsid(ev.ident):
                                    self.untrack_pid(ev.ident)
                                    continue
                            except ProcessLookupError:
                                continue

                            job = Job(self)
                            job.load_anonymous(pjob, ev.ident)
                            self.jobs[job.id] = job
                            self.logger.info('Added job {0}'.format(job.label))

    def track_pid(self, pid):
        ev = select.kevent(
            pid,
            select.KQ_FILTER_PROC,
            select.KQ_EV_ADD | select.KQ_EV_ENABLE,
            select.KQ_NOTE_EXIT | select.KQ_NOTE_EXEC | select.KQ_NOTE_FORK | select.KQ_NOTE_TRACK,
            0, 0
        )

        self.kq.control([ev], 0)

    def untrack_pid(self, pid):
        ev = select.kevent(
            pid,
            select.KQ_FILTER_PROC,
            select.KQ_EV_DELETE,
            0, 0, 0
        )

        self.kq.control([ev], 0)

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('serviced')
                self.client.enable_server(self.rpc)
                self.client.resume_service('serviced.control')
                self.client.resume_service('serviced.management')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-s', metavar='SOCKET', default=DEFAULT_SOCKET_ADDRESS, help='Socket address to listen on')
        args = parser.parse_args()
        configure_logging('/var/log/serviced.log', 'DEBUG')

        setproctitle.setproctitle('serviced')
        self.logger.info('Started')
        self.init_dispatcher()
        self.init_server(args.s)
        self.event_loop()


if __name__ == '__main__':
    c = Context()
    c.main()
