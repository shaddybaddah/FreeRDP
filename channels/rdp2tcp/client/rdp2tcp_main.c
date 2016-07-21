/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * rdp2tcp Virtual Channel Extension
 *
 * Copyright 2015 Artur Zaprzala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/uio.h>
#include <assert.h>

#include <winpr/thread.h>
#include <winpr/collections.h>
#include <freerdp/svc.h>

#define RDP2TCP_CHAN_NAME "rdp2tcp"

typedef struct {
	int readfd;
	int writefd;
	pid_t pid;
	DWORD openHandle;
	HANDLE copyThread;
	HANDLE writeComplete;
	CHANNEL_ENTRY_POINTS_FREERDP channelEntryPoints;
	char buffer[4096];
} Plugin;

static wListDictionary *initHandles;
static wListDictionary *openHandles;

static void add_init_handle_data(void *pInitHandle, void *data) {
	ListDictionary_Add(initHandles, pInitHandle, data);
}

static void *get_init_handle_data(void *pInitHandle) {
	return ListDictionary_GetItemValue(initHandles, pInitHandle);
}

static void remove_init_handle_data(void *pInitHandle) {
	ListDictionary_Remove(initHandles, pInitHandle);
}

static void add_open_handle_data(DWORD openHandle, void *data) {
	ListDictionary_Add(openHandles, (void *)(size_t)openHandle, data);
}

static void *get_open_handle_data(DWORD openHandle) {
	return ListDictionary_GetItemValue(openHandles, (void *)(size_t)openHandle);
}

static void remove_open_handle_data(DWORD openHandle) {
	ListDictionary_Remove(openHandles, (void *)(size_t)openHandle);
}


static int init_external_addin(Plugin *plugin, char *args) {
	int readpipe[2], writepipe[2];
	pid_t child;

	if (pipe(readpipe) < 0 || pipe(writepipe) < 0) {
		perror("pipes for addin");
		return -1;
	}
	if ((child = fork()) < 0) {
		perror("fork for addin");
		return -1;
	}
	if (child) {
		/* Close child end fd's */
		close(readpipe[1]);
		close(writepipe[0]);
		plugin->readfd = readpipe[0];
		plugin->writefd = writepipe[1];
		plugin->pid = child;
		return 0;
	}

	/* Child */
	/* Set stdin and stdout of child to relevant pipe ends */
	dup2(writepipe[0], 0);
	dup2(readpipe[1], 1);
	/* Close all fds as they are not needed now */
	close(readpipe[0]);
	close(readpipe[1]);
	close(writepipe[0]);
	close(writepipe[1]);

	/* Go through the list of args, adding each to argv */
	char *argv[256];
	int i = 0;
	for (; i<255; ++i) {
		argv[i] = args;
		args = strchr(args, ':');
		if (!args) {
			++i;
			break;
		}
		*args++ = '\0';
	}
	argv[i] = NULL;
	execvp(argv[0], argv);
	perror("Error executing child");
	_exit(128);
}

static DWORD copyThread(void *data) {
	Plugin *plugin = (Plugin *)data;
	while (1) {
		ssize_t n = read(plugin->readfd, plugin->buffer, sizeof plugin->buffer);
		if (n == -1)
			return -1;
		if (0) {
			printf(">%3u ", (unsigned)n);
			for (int i=0; i<n && i<32; ++i)
				printf("%02hhx", plugin->buffer[i]);
			puts("");
		}
		if (plugin->channelEntryPoints.pVirtualChannelWrite(plugin->openHandle, plugin->buffer, n, NULL) != CHANNEL_RC_OK)
			return -1;
		WaitForSingleObject(plugin->writeComplete, INFINITE);
		ResetEvent(plugin->writeComplete);
	}
	return 0;
}

static void VCAPITYPE VirtualChannelOpenEvent(DWORD openHandle, UINT event, LPVOID pData, UINT32 dataLength, UINT32 totalLength, UINT32 dataFlags) {
	Plugin *plugin = get_open_handle_data(openHandle);
	switch (event) {
		case CHANNEL_EVENT_DATA_RECEIVED:;
			ssize_t status;
			if (0) {
				printf("<%c%u/%u ", dataFlags & CHANNEL_FLAG_FIRST ? ' ': '+', totalLength, dataLength);
				for (int i=0; i<dataLength && i<16; ++i)
					printf("%02hhx", ((char *)pData)[i]);
				if (dataLength>16) {
					printf("...");
					for (int i=dataLength-16; i<dataLength; ++i)
						printf("%02hhx", ((char *)pData)[i]);
				}
				puts("");
			}
			if (dataFlags & CHANNEL_FLAG_FIRST) {
				// Prepend the block with the block size so the add-in can identify blocks
				struct iovec iov[] = {
					{.iov_base = &totalLength, .iov_len = sizeof(totalLength)},
					{.iov_base = pData, .iov_len = dataLength}
				};
				status = writev(plugin->writefd, iov, 2);
			} else
				status = write(plugin->writefd, pData, dataLength);
			if (status == -1)
				plugin->channelEntryPoints.pVirtualChannelClose(openHandle);
			break;
		case CHANNEL_EVENT_WRITE_COMPLETE:
			SetEvent(plugin->writeComplete);
			break;
	}
}

static void VCAPITYPE VirtualChannelInitEvent(LPVOID pInitHandle, UINT event, LPVOID pData, UINT dataLength) {
	Plugin *plugin = get_init_handle_data(pInitHandle);
	switch (event) {
		case CHANNEL_EVENT_CONNECTED:
			if (plugin->channelEntryPoints.pVirtualChannelOpen(pInitHandle, &plugin->openHandle, RDP2TCP_CHAN_NAME, VirtualChannelOpenEvent) != CHANNEL_RC_OK)
				return;
			add_open_handle_data(plugin->openHandle, plugin);
			plugin->writeComplete = CreateEvent(NULL, TRUE, FALSE, NULL);
			plugin->copyThread = CreateThread(NULL, 0, copyThread, plugin, 0, NULL);
			break;
		case CHANNEL_EVENT_DISCONNECTED:
			break;
		case CHANNEL_EVENT_TERMINATED:
			if (plugin->copyThread) {
				TerminateThread(plugin->copyThread, 0);
				CloseHandle(plugin->writeComplete);
				remove_open_handle_data(plugin->openHandle);
			}
			remove_init_handle_data(pInitHandle);

			close(plugin->writefd);
			close(plugin->readfd);
			if (plugin->pid)
				kill(plugin->pid, SIGUSR1);
			free(plugin);
			break;
	}
}

BOOL VCAPITYPE VirtualChannelEntry(PCHANNEL_ENTRY_POINTS pEntryPoints) {
	if (!initHandles)
		initHandles = ListDictionary_New(TRUE);
	if (!openHandles)
		openHandles = ListDictionary_New(TRUE);

	Plugin *plugin = (Plugin *)calloc(1, sizeof(Plugin));
	if (!plugin)
		return FALSE;

	CHANNEL_ENTRY_POINTS_FREERDP *pEntryPointsEx = (CHANNEL_ENTRY_POINTS_FREERDP *)pEntryPoints;
	assert(pEntryPointsEx->cbSize >= sizeof(CHANNEL_ENTRY_POINTS_FREERDP) && pEntryPointsEx->MagicNumber == FREERDP_CHANNEL_MAGIC_NUMBER);
	//*pEntryPointsEx->ppInterface = (void *)plugin;
	plugin->channelEntryPoints = *pEntryPointsEx;
	plugin->channelEntryPoints.pInterface = *plugin->channelEntryPoints.ppInterface;
	plugin->channelEntryPoints.ppInterface = &plugin->channelEntryPoints.pInterface;
	
	if (init_external_addin(plugin, plugin->channelEntryPoints.pExtendedData) < 0)
		return FALSE;

	CHANNEL_DEF channelDef = {
		.name = RDP2TCP_CHAN_NAME,
		.options =
			CHANNEL_OPTION_INITIALIZED |
			CHANNEL_OPTION_ENCRYPT_RDP |
			CHANNEL_OPTION_COMPRESS_RDP
	};
	LPVOID pInitHandle;
	if (pEntryPoints->pVirtualChannelInit(&pInitHandle, &channelDef, 1, VIRTUAL_CHANNEL_VERSION_WIN2000, VirtualChannelInitEvent) != CHANNEL_RC_OK)
		return FALSE;
	add_init_handle_data(pInitHandle, plugin);
	return TRUE;
}

// vim:ts=4
