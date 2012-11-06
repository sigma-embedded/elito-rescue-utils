/*	--*- c -*--
 * Copyright (C) 2012 Enrico Scholz <enrico.scholz@sigma-chemnitz.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sysexits.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <grp.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/file.h>

#include <ccgi.h>

#ifndef LOCKFILE
#  define LOCKFILE	"/var/lock/image.lock"
#endif

struct tmpdir_info {
	char const	*name;
	char		*template;
	int		fd;
};

static int	read_all(int fd, void *buf, size_t len)
{
	while (len > 0) {
		ssize_t		l =  read(fd, buf, len);

		if (l == 0)
			break;
		else if (l > 0) {
			buf += l;
			len -= l;
		} else if (errno == EINTR)
			continue;
		else {
			perror("read()");
			return -1;
		}
	}

	if (len > 0) {
		fprintf(stderr, "read_all(): EOF\n");
		return -1;
	}

	return 0;
}

static ssize_t	read_string(int fd, char *buf, size_t max_len)
{
	size_t		req_len;

	if (read_all(fd, &req_len, sizeof req_len) < 0)
		return -1;

	if (req_len >= max_len - 1) {
		fprintf(stderr, "req_len exceeds max_len (%zu >= %zu-1)\n",
			req_len, max_len);
		return -1;
	}

	if (read_all(fd, buf, req_len) < 0)
		return -1;

	buf[req_len] = '\0';
	return req_len;
}

static int	tmpdir_close(struct tmpdir_info *dir)
{
	int	rc = 0;

	if (dir->template == NULL)
		return 0;			/* already closed */

	close(dir->fd);

	if (rmdir(dir->name) < 0)
		rc = -1;

	free(dir->template);
	dir->template = NULL;

	return rc;
}

static void	cleanup_tmpdir(int v, void *ptr)
{
	(void)v;

	tmpdir_close(ptr);
	free(ptr);
}

static bool	g_headers_send = false;
static int	g_fd_err = -1;

static void	send_http_error(int v, void *ptr)
{
	(void)ptr;

	if (!g_headers_send) {
		printf("Status: 500 Internal server error\r\n"
		       "\r\n");

		g_headers_send = true;
	}
	
	if (v) {
		loff_t	offs = 0;

		printf("error (%d)\r\n----------------------------\r\n", v);

		fclose(stderr);
		fflush(stdout);

		while (splice(g_fd_err, &offs, STDOUT_FILENO, NULL,
			      1024*1024, 0) > 0)
			;

		printf("\r\n----------------------------\r\n");
	}
}

static struct tmpdir_info	*tmpdir_create(char const *template)
{
	struct tmpdir_info	*res = calloc(1, sizeof *res);

	if (!res) {
		perror("calloc()");
		goto err0;
	}

	res->fd = -1;
	res->template = strdup(template);
	if (!res->template) {
		perror("strdup()");
		goto err;
	}


	res->name = mkdtemp(res->template);
	if (res->name == NULL) {
		perror("mkdtemp()");
		goto err;
	}

	res->fd = open(res->name, O_DIRECTORY | O_CLOEXEC);
	if (res->fd < 0) {
		perror("open(<tmpdir>)");
		goto err;
	}

	if (on_exit(cleanup_tmpdir, res) != 0) {
		perror("on_exit()");
		goto err;
	}

	return res;

err:
	if (res->fd != -1)
		close(res->fd);
	if (res->name)
		rmdir(res->name);
	free(res->template);
	free(res);

err0:
	return NULL;
}

static int run_update_script(int fd, int dir_fd)
{
	pid_t		pid;
	int		status;

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		return EX_OSERR;
	}

	if (pid == 0) {
		if (fchdir(dir_fd) < 0) {
			perror("fchdir(<tmpdir>)");
			_exit(EX_OSERR);
		}
		close(dir_fd);

		if (dup2(fd, 0) < 0) {
			perror("dup2()");
			_exit(EX_OSERR);
		}
		if (fd != 0)
			close(fd);

		execlp("/usr/bin/elito-stream-decode-wrap",
		       "/usr/bin/elito-stream-decode-wrap",
		       NULL);

		_exit(EX_OSERR);
	}

	close(fd);
	waitpid(pid, &status, 0);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	return EX_SOFTWARE;
}

static bool redir_stderr(void)
{
	char		template[] = "/tmp/upload-err.XXXXXX";
	int		fd = mkostemp(template, O_CLOEXEC);

	if (fd < 0) {
		perror("mkstemp(<stderr>)");
		return false;
	}

	unlink(template);

	fflush(stderr);
	if (dup2(fd, STDERR_FILENO) < 0) {
		perror("dup2(<stderr>)");
		close(fd);
		return false;
	}

	g_fd_err = fd;

	return true;
}

int main(void)
{
	struct tmpdir_info	*upload_dir = tmpdir_create("/tmp/upload-XXXXXX");
	struct tmpdir_info	*work_dir = tmpdir_create("/tmp/work-XXXXXX");

	int		pipe_fd[2];
	pid_t		pid;

	gid_t		gid = 100;
	uid_t		uid = 100;

	int		lock_fd;

	on_exit(send_http_error, NULL);

	if (!redir_stderr())
		return EX_OSERR;

	lock_fd = open(LOCKFILE, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
		       0600);
	if (lock_fd < 0) {
		perror("open(<lockfile>)");
		return EX_OSERR;
	}

	if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
		perror("flock()");
		return EX_TEMPFAIL;
	}

	if (!upload_dir || !work_dir)
		return EX_CANTCREAT;

	if (pipe(pipe_fd) < 0) {
		perror("pipe()");
		return EX_OSERR;
	}

	if (fchown(upload_dir->fd, -1, gid) < 0 ||
	    fchmod(upload_dir->fd, 0770) < 0) {
		perror("chown/chmod(<uploaddir>)");
		return EX_NOPERM;
	}

	printf("Status: 200 ok\r\n"
	       "Content-Type: text/plain\r\n"
	       "Cache-Control: no-cache\r\n"
	       "\r\n"
	       "Receiving stream...");
	fflush(stdout);
	g_headers_send = true;

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		return EX_OSERR;
	} else if (pid == 0)  {
		CGI_varlist	*vl;
		char const	*value;
		char const	*fname;
		struct dirent	**namelist;
		int		n;


		close(pipe_fd[0]);

		close(upload_dir->fd);
		close(work_dir->fd);

		n = scandir("/proc/self/fd", &namelist, NULL, alphasort);
		if (n < 0) {
			perror("scandir()");
			_exit(1);
		}

		while (n--) {
			char	*errptr;
			int	fd = strtoul(namelist[n]->d_name, &errptr, 10);

			if (*errptr != '\0')
				continue;

			if (fd == pipe_fd[1] || fd == 0 || fd == 2)
				continue;

			close(fd);
		}

		free(namelist);

		open("/dev/null", O_WRONLY); /* --> becomes fd 1 */

		if (chroot(upload_dir->name) < 0) {
			perror("chroot(<uploaddir>)");
			_exit(1);
		}

		if (chdir("/") < 0) {
			perror("chdir(<uploaddir>)");
			_exit(1);
		}

		if (setgroups(1, &gid) <0 ||
		    setresgid(gid, gid, gid) < 0 ||
		    setresuid(uid, uid, uid) < 0) {
			perror("drop-permissions()");
			_exit(1);
		}

		/* \note: CGI_get_post() does not make proper error checking;
		 * out-of-diskspace conditions will not be detected! */
		vl = CGI_get_post(NULL, "cgi-upload-XXXXXX");
		if (vl == NULL) {
			fprintf(stderr, "CGI_get_all() failed\n");
			_exit(1);
		}

		fname = "image";
		value = CGI_lookup(vl, fname);
		if (!value) {
			fprintf(stderr, "missing file data\n");
			_exit(1);
		}

		{
			size_t	l0 = strlen(fname);
			size_t	l1 = strlen(value);

			write(pipe_fd[1], &l0, sizeof l0);
			write(pipe_fd[1], fname, l0);

			write(pipe_fd[1], &l1, sizeof l1);
			write(pipe_fd[1], value, l1);

			close(pipe_fd[1]);
		}

		CGI_free_varlist(vl);

		fflush(stdout);
		_exit(0);
	} else {
		char		filetype[128];
		char		filename[64];
		struct stat	st;
		int		fd;
		int		rc;

		close(0);
		close(pipe_fd[1]);

		open("/dev/null", O_RDONLY); /* becomes fd 0 */

		if (read_string(pipe_fd[0], filetype, sizeof filetype) < 0 ||
		    read_string(pipe_fd[0], filename, sizeof filename) < 0) {
			kill(SIGKILL, pid);
			return EX_DATAERR;
		}

		close(pipe_fd[0]);

		if (renameat(upload_dir->fd, filename,
			     work_dir->fd, filetype) < 0) {
			perror("renameat()");
			return EX_OSERR;
		}

		wait(NULL);

		if (tmpdir_close(upload_dir) < 0) {
			fprintf(stderr, "failed to cleanup upload dir\n");
			return EX_OSERR;
		}

		if (fstatat(work_dir->fd, filetype, &st, AT_SYMLINK_NOFOLLOW) < 0) {
			perror("fstatat()");
			return EX_OSERR;
		}

		if (!S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
			fprintf(stderr, "huch... strange filetype\n");
			return EX_OSERR;
		}

		if (fchownat(work_dir->fd, filetype,
			     getuid(), getgid(), AT_SYMLINK_NOFOLLOW) < 0) {
			perror("fchownat()");
			return EX_OSERR;
		}

		if (fchmodat(work_dir->fd, filetype, 0644, 0) < 0) {
			perror("fchmodat()");
			return EX_OSERR;
		}

		fd = openat(work_dir->fd, filetype, O_RDONLY);
		if (fd < 0) {
			perror("openat(<file>)");
			return EX_OSERR;
		}

		if (unlinkat(work_dir->fd, filetype, 0)) {
			perror("unlinkat(<filetype>)");
			return EX_OSERR;
		}

		printf("done\r\n"
		       "Processing stream...");
		fflush(stdout);

		rc = run_update_script(fd, work_dir->fd);
		if (rc)
			return rc;

		printf("done\r\n"
		       "finished");
	}

	return 0;
}
