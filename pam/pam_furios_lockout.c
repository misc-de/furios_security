// SPDX-FileCopyrightText: Copyright (c) 2026 misc-de
// SPDX-License-Identifier: MIT
//
// Locks the phosh lock screen for a while after failed attempts, a little
// longer each time: after 3 failures 5 minutes, then 10, 15, 30, 60, 120,
// 240, 480, and from there each lock twice the one before - 16 hours, 32,
// 64, ... - up to a ceiling of one year (MAX_LOCK), which is there only so
// the arithmetic cannot overflow. Failures are never forgotten because time
// passed: a guesser who waits out every lock, or spaces the attempts days
// apart, climbs the same ladder. Only a successful unlock starts over.
//
// Why not pam_faillock: its lock time is fixed. And why this shape - one
// line before pam_unix, one in the account stack - rather than faillock's
// preauth/authfail/authsucc: pam-auth-update can place a line before the
// primary block and one after it, but not one on pam_unix's failure path.
// So every attempt is counted when it starts, and the count is cleared when
// the account stack runs, which phosh only reaches after a correct PIN.
// Three attempts that never got there are three failures.
//
// It fails open. Any doubt - another service, a state file that cannot be
// read or written, a user it cannot look up - answers PAM_IGNORE, so the
// worst this module can do when broken is nothing. A lock screen that cannot
// be unlocked any more is the one outcome that must not come out of it.
//
// State lives with the user (~/.local/state/furios-lockout/state), because
// phosh runs PAM as that user and nothing else would be writable. Whoever
// can write there already has a shell as that user and is past the lock
// screen anyway.
//
// Arguments:
//   preauth            in the auth stack: check the lock, count the attempt
//   deny=N             failures before a lock (default 3)
//   schedule=a,b,...   lock lengths in minutes (default 5,10,15,30,60,120,240,480);
//                      past the last one, each lock doubles
//   interval=S         accepted and ignored. It used to forget failures
//                      further apart than S seconds, which let a slow guesser
//                      try 3 PINs every 15 minutes forever without ever
//                      reaching a longer lock. Still parsed so an old stack
//                      line naming it keeps working.
//   services=a,b       which PAM services it acts for (default phosh)
//   quiet              no message to the front end - phosh cannot show one
//                      and logs "conversation failed" for every attempt
//   dir=PATH           keep state in PATH/<user> instead of the home - for
//                      the tests, which must not touch the real state

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_ext.h>
#include <security/pam_modules.h>

#define MAX_STEPS 16
/* Ceiling for the doubling - one year. Not a policy (twenty-odd locks in,
 * the PIN has been tried about sixty times); it keeps lock_start + lock_len
 * far from overflowing a long. */
#define MAX_LOCK (365L * 24 * 3600)

struct opts {
	int preauth;
	int quiet;
	int deny;
	int nsteps;
	long steps[MAX_STEPS];          /* seconds */
	const char *services;
	const char *dir;
};

struct state {
	long pending;                   /* attempts not followed by a success */
	long strikes;                   /* locks since the last success */
	long lock_start;
	long lock_len;
	long last;                      /* time of the last attempt */
};

static void parse(int argc, const char **argv, struct opts *o)
{
	static const long dflt[] = { 5, 10, 15, 30, 60, 120, 240, 480 };

	o->preauth = 0;
	o->quiet = 0;
	o->deny = 3;
	o->services = "phosh";
	o->dir = NULL;
	o->nsteps = sizeof(dflt) / sizeof(dflt[0]);
	for (int i = 0; i < o->nsteps; i++)
		o->steps[i] = dflt[i] * 60;

	for (int i = 0; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "preauth") == 0) {
			o->preauth = 1;
		} else if (strcmp(a, "quiet") == 0) {
			o->quiet = 1;
		} else if (strncmp(a, "deny=", 5) == 0) {
			int n = atoi(a + 5);
			if (n > 0)
				o->deny = n;
		} else if (strncmp(a, "interval=", 9) == 0) {
			/* ignored - see the header */
		} else if (strncmp(a, "dir=", 4) == 0 && a[4] == '/') {
			o->dir = a + 4;
		} else if (strncmp(a, "services=", 9) == 0) {
			o->services = a + 9;
		} else if (strncmp(a, "schedule=", 9) == 0) {
			long v[MAX_STEPS];
			int n = 0;
			const char *p = a + 9;
			while (*p && n < MAX_STEPS) {
				char *end;
				long m = strtol(p, &end, 10);
				if (end == p || m <= 0)
					break;
				if (m > MAX_LOCK / 60)
					m = MAX_LOCK / 60;
				v[n++] = m * 60;
				p = (*end == ',') ? end + 1 : end;
				if (*end != ',')
					break;
			}
			/* A schedule that did not parse keeps the default rather
			 * than becoming "no lock at all". */
			if (n > 0) {
				o->nsteps = n;
				memcpy(o->steps, v, n * sizeof(long));
			}
		}
	}
}

/* The length of lock number strikes+1: the schedule, then the last step
 * doubled for every lock beyond it, saturating at MAX_LOCK. */
static long lock_length(const struct opts *o, long strikes)
{
	long len;

	if (strikes < o->nsteps)
		return o->steps[strikes] < MAX_LOCK ? o->steps[strikes] : MAX_LOCK;
	len = o->steps[o->nsteps - 1];
	for (long k = strikes - (o->nsteps - 1); k > 0 && len < MAX_LOCK; k--)
		len *= 2;
	return len < MAX_LOCK ? len : MAX_LOCK;
}

static int service_listed(const char *list, const char *svc)
{
	size_t len = strlen(svc);
	const char *p = list;

	while (*p) {
		const char *comma = strchr(p, ',');
		size_t n = comma ? (size_t)(comma - p) : strlen(p);
		if (n == len && strncmp(p, svc, n) == 0)
			return 1;
		if (!comma)
			break;
		p = comma + 1;
	}
	return 0;
}

/* The user's state file, or -1 when this module has no business here: the
 * process does not run as that user, or the user cannot be looked up. */
static int state_path(pam_handle_t *pamh, const struct opts *o,
		      char *dir, size_t dlen, char *file, size_t flen)
{
	const char *user = NULL;
	struct passwd pw, *res = NULL;
	char buf[4096];

	if (pam_get_item(pamh, PAM_USER, (const void **)&user) != PAM_SUCCESS
	    || !user || !*user)
		return -1;
	if (getpwnam_r(user, &pw, buf, sizeof(buf), &res) != 0 || !res)
		return -1;
	/* Never create files in somebody's home as somebody else. */
	if (geteuid() != pw.pw_uid)
		return -1;
	if (o->dir) {
		if (snprintf(dir, dlen, "%s/%s", o->dir, user) >= (int)dlen)
			return -1;
	} else if (snprintf(dir, dlen, "%s/.local/state/furios-lockout",
			    pw.pw_dir) >= (int)dlen) {
		return -1;
	}
	if (snprintf(file, flen, "%s/state", dir) >= (int)flen)
		return -1;
	return 0;
}

/* Missing is a clean slate; unreadable or garbled is -1. */
static int load(const char *file, struct state *s)
{
	FILE *f;
	int n;

	memset(s, 0, sizeof(*s));
	f = fopen(file, "r");
	if (!f)
		return errno == ENOENT ? 0 : -1;
	n = fscanf(f, "%ld %ld %ld %ld %ld", &s->pending, &s->strikes,
		   &s->lock_start, &s->lock_len, &s->last);
	fclose(f);
	if (n != 5 || s->pending < 0 || s->strikes < 0 || s->lock_len < 0) {
		memset(s, 0, sizeof(*s));
		return -1;
	}
	return 0;
}

static int mkdirs(const char *dir)
{
	char tmp[4096];
	size_t len = strlen(dir);

	if (len >= sizeof(tmp))
		return -1;
	memcpy(tmp, dir, len + 1);
	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
			return -1;
		*p = '/';
	}
	if (mkdir(tmp, 0700) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

/* Through a temp file and rename: a half-written state must not read as a
 * clean slate. */
static int save(const char *dir, const char *file, const struct state *s)
{
	char tmp[4200];
	int fd;
	FILE *f;

	if (mkdirs(dir) != 0)
		return -1;
	if (snprintf(tmp, sizeof(tmp), "%s.tmp", file) >= (int)sizeof(tmp))
		return -1;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -1;
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(tmp);
		return -1;
	}
	fprintf(f, "%ld %ld %ld %ld %ld\n", s->pending, s->strikes,
		s->lock_start, s->lock_len, s->last);
	if (fflush(f) != 0 || fsync(fd) != 0) {
		fclose(f);
		unlink(tmp);
		return -1;
	}
	fclose(f);
	if (rename(tmp, file) != 0) {
		unlink(tmp);
		return -1;
	}
	return 0;
}

static int refuse(pam_handle_t *pamh, const struct opts *o, long left)
{
	/* phosh does not show conversation messages today (hence "quiet" in
	 * the profile); other front ends do. */
	if (!o->quiet)
		pam_error(pamh, "Too many failed attempts. Try again in %ld:%02ld.",
		  left / 60, left % 60);
	return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	struct opts o;
	struct state s;
	const char *svc = NULL;
	char dir[4096], file[4200];
	long now = (long)time(NULL);
	(void)flags;

	parse(argc, argv, &o);
	if (!o.preauth)
		return PAM_IGNORE;
	if (pam_get_item(pamh, PAM_SERVICE, (const void **)&svc) != PAM_SUCCESS
	    || !svc || !service_listed(o.services, svc))
		return PAM_IGNORE;
	if (state_path(pamh, &o, dir, sizeof(dir), file, sizeof(file)) != 0)
		return PAM_IGNORE;
	if (load(file, &s) != 0) {
		pam_syslog(pamh, LOG_WARNING, "state %s unreadable, not counting", file);
		return PAM_IGNORE;
	}

	if (s.lock_len > 0) {
		/* The clock went back: keep the lock, but no longer than it
		 * was meant to last from now. */
		if (now < s.lock_start)
			s.lock_start = now;
		if (now < s.lock_start + s.lock_len) {
			save(dir, file, &s);
			return refuse(pamh, &o, s.lock_start + s.lock_len - now);
		}
		s.lock_len = 0;
	}

	/* No forgetting with time: failures far apart are still failures,
	 * and only pam_sm_acct_mgmt - a correct PIN - clears them. */
	if (s.pending >= o.deny) {
		/* The lock runs from the last failure, not from this attempt. */
		s.lock_start = (s.last > 0 && s.last <= now) ? s.last : now;
		s.lock_len = lock_length(&o, s.strikes);
		s.strikes++;
		s.pending = 0;
		pam_syslog(pamh, LOG_NOTICE,
			   "%d failed attempts: lock screen locked for %ld min (lock %ld)",
			   o.deny, s.lock_len / 60, s.strikes);
		if (save(dir, file, &s) != 0)
			return PAM_IGNORE;
		if (now < s.lock_start + s.lock_len)
			return refuse(pamh, &o, s.lock_start + s.lock_len - now);
		s.lock_len = 0;
	}

	s.pending++;
	s.last = now;
	if (save(dir, file, &s) != 0) {
		pam_syslog(pamh, LOG_WARNING, "cannot write %s, not counting", file);
		return PAM_IGNORE;
	}
	return PAM_IGNORE;
}

/* Reached only after a correct PIN: everything starts over. */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
				int argc, const char **argv)
{
	struct opts o;
	struct state s;
	const char *svc = NULL;
	char dir[4096], file[4200];
	(void)flags;

	parse(argc, argv, &o);
	if (pam_get_item(pamh, PAM_SERVICE, (const void **)&svc) != PAM_SUCCESS
	    || !svc || !service_listed(o.services, svc))
		return PAM_IGNORE;
	if (state_path(pamh, &o, dir, sizeof(dir), file, sizeof(file)) != 0)
		return PAM_IGNORE;
	if (load(file, &s) == 0 && !s.pending && !s.strikes && !s.lock_len)
		return PAM_IGNORE;
	memset(&s, 0, sizeof(s));
	save(dir, file, &s);
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
			      int argc, const char **argv)
{
	(void)pamh; (void)flags; (void)argc; (void)argv;
	return PAM_IGNORE;
}
