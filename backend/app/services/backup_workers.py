"""Keep Celery consumers paused while a database backup is restored."""

import fcntl
import os
import time

from app import utils


RESTORE_LOCK = '/tmp/arl_restore.lock'
SCAN_QUEUES = frozenset(('arltask', 'arltask_heavy', 'arltask_light', 'arlgithub'))
TERMINAL = ('done', 'error', 'stop')


class RestoreWorkers:
    def __init__(self, force=False, timeout=30):
        from app.celerytask import celery
        self.app = celery
        self.control = celery.control
        self.force = force
        self.timeout = timeout
        self.paused = []
        self.workers = []
        self.lock_fd = None
        self.restore_started = False

    def _acknowledged(self, replies, workers):
        acknowledged = {worker for reply in (replies or []) for worker, result in reply.items()
                        if isinstance(result, dict) and 'ok' in result and 'error' not in result}
        if not set(workers).issubset(acknowledged):
            raise RuntimeError('未收到全部 Worker 的确认，已阻止数据库恢复')

    def _snapshot(self, method):
        replies = getattr(self.control.inspect(destination=self.workers, timeout=3), method)()
        if not isinstance(replies, dict) or not set(self.workers).issubset(replies):
            raise RuntimeError('无法确认全部 Worker 的运行状态，已阻止数据库恢复')
        return [task for worker in self.workers for task in replies[worker]]

    def _queue_operation(self, purge=False):
        count = 0
        with self.app.connection_for_write() as connection:
            channel = connection.default_channel
            for queue in sorted({queue for _, queue in self.paused}):
                if purge:
                    channel.queue_purge(queue=queue)
                else:
                    count += channel.queue_declare(queue=queue, passive=True)[1]
        return count

    def _unfinished(self):
        for name in ('task', 'github_task'):
            for task in utils.conn_db(name).find({'status': {'$nin': list(TERMINAL)}}, {'celery_id': 1}):
                yield task

    def _mark_stopped(self):
        for name in ('task', 'github_task'):
            utils.conn_db(name).update_many(
                {'status': {'$nin': list(TERMINAL)}},
                {'$set': {'status': 'stop', 'end_time': utils.curr_date()}},
            )

    def _resume(self):
        failures = []
        for worker, queue in reversed(self.paused):
            try:
                self._acknowledged(self.control.add_consumer(
                    queue, destination=[worker], reply=True, timeout=3), [worker])
            except Exception as exc:
                failures.append(exc)
        self.paused.clear()
        if failures:
            raise RuntimeError('数据库操作已结束，但部分 Worker 队列恢复失败，请重启 Worker') from failures[0]

    def _unlock(self):
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def __enter__(self):
        self.lock_fd = os.open(RESTORE_LOCK, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._unlock()
            raise RuntimeError('已有数据库恢复正在执行')
        try:
            queues = self.control.inspect(timeout=3).active_queues()
            if not isinstance(queues, dict) or not queues:
                raise RuntimeError('无法确认 Worker 状态，已阻止数据库恢复；请检查 Worker 和消息队列')
            for worker, entries in queues.items():
                for entry in entries:
                    queue = entry.get('name')
                    if queue not in SCAN_QUEUES:
                        continue
                    # Record before sending, so an uncertain reply also gets a
                    # compensating resume if preflight fails.
                    self.paused.append((worker, queue))
                    self._acknowledged(self.control.cancel_consumer(
                        queue, destination=[worker], reply=True, timeout=3), [worker])
            self.workers = sorted({worker for worker, _ in self.paused})
            if not self.workers:
                raise RuntimeError('未找到可确认状态的扫描 Worker，已阻止数据库恢复')

            active = self._snapshot('active')
            reserved = self._snapshot('reserved')
            scheduled = self._snapshot('scheduled')
            unfinished = list(self._unfinished())
            queued = self._queue_operation()
            if (active or reserved or scheduled or unfinished or queued) and not self.force:
                raise RuntimeError('存在运行中或排队中的任务，请等待完成或确认强制恢复')

            task_ids = {task['id'] for task in active + reserved if task.get('id')}
            task_ids.update(task['request']['id'] for task in scheduled if task.get('request', {}).get('id'))
            task_ids.update(str(task['celery_id']) for task in unfinished if task.get('celery_id'))
            if task_ids:
                self._acknowledged(self.control.revoke(
                    sorted(task_ids), terminate=True, signal='SIGTERM',
                    destination=self.workers, reply=True, timeout=3), self.workers)
            deadline = time.monotonic() + self.timeout
            while self._snapshot('active'):
                if time.monotonic() >= deadline:
                    raise RuntimeError('等待 Worker 停止超时，已阻止数据库恢复')
                time.sleep(0.2)
            if self.force:
                self._queue_operation(purge=True)
                self._mark_stopped()
            return self
        except Exception:
            try:
                self._resume()
            finally:
                self._unlock()
            raise

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type and self.restore_started:
                raise RuntimeError('恢复未完成，扫描队列保持暂停；修复并确认数据后再重启 Worker') from exc
            if not exc_type:
                # Discard jobs published against the old database while the
                # consumers were paused; their task records have been replaced.
                self._queue_operation(purge=True)
                self._mark_stopped()
            self._resume()
        finally:
            self._unlock()
