/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2001  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef SER2NET_LOCKING_H
#define SER2NET_LOCKING_H

#ifdef USE_PTHREADS

#include <pthread.h>

/* #define LOCKING_DEBUG */

#ifdef LOCKING_DEBUG
#define LOCKDEBUG_PRINT(name, lock) printf("%s %p: %s:%d\n", name, \
					   &lock, __FILE__, __LINE__)
#else
#define LOCKDEBUG_PRINT(name, lock) do { } while (0)
#endif

#define DEFINE_LOCK(scope, name) scope pthread_mutex_t name;
#define DEFINE_LOCK_INIT(scope, name) scope pthread_mutex_t name \
				= PTHREAD_MUTEX_INITIALIZER;
#define INIT_LOCK(lock) pthread_mutex_init(&lock, NULL)
#define FREE_LOCK(lock) pthread_mutex_destroy(&lock)
#define LOCK(lock) do { LOCKDEBUG_PRINT("LOCK", lock); \
			pthread_mutex_lock(&lock); } while (0)
#define UNLOCK(lock) do { LOCKDEBUG_PRINT("UNLOCK", lock); \
			  pthread_mutex_unlock(&lock); } while (0)

#else

#define DEFINE_LOCK(scope, name)
#define DEFINE_LOCK_INIT(scope, name)
#define INIT_LOCK(lock) do { } while (0)
#define FREE_LOCK(lock) do { } while (0)
#define LOCK(lock) do { } while (0)
#define UNLOCK(lock) do { } while (0)

#endif

#endif /* SER2NET_LOCKING_H */
