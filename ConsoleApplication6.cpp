#include <stdio.h>
#include <WinSock2.h>
#include <iostream>
#include <Windows.h>
#include <comdef.h>
#include <stdio.h>
#include <vector>
#include <string>

using namespace std;


#define MAX_DATA_SIZE 255
#define DATA_SIZE 1000


struct MockedFile {
  char size[MAX_DATA_SIZE];
  char* data;
};

// Prepares the fake file
void MockFileFormat(struct MockedFile* mock) {
  char size[1];
  size[0] = DATA_SIZE;

  char* data = (char*) malloc(DATA_SIZE);
  memset(data, 'A', DATA_SIZE);

  memcpy(mock->size, size, 1);
  mock->data = data;
}

int prob1(int args, char** argv) {
  // Pretend this gives us the fake file (or a network packet)
  struct MockedFile mock;
  MockFileFormat(&mock);

  // The size field is copied to a one-byte buffer
  char sizeBuf[1];
  memcpy(sizeBuf, mock.size, 1);

  // char by default is signed, which means this check can only
  // handle range between -128 to 127, and may result an integer
  // overflow
  char size = sizeBuf[0];
  printf("Data size is %d\n", size);
  if (size < MAX_DATA_SIZE) {
    char buffer[MAX_DATA_SIZE];
    memset(buffer, '\0', MAX_DATA_SIZE);
    memcpy(buffer, mock.data, size);
    printf("%s\n", buffer);
  }

  return 0;
}

#pragma comment(lib, "Ws2_32.lib")
int prob2(int args, char** argv) {
  /*
  *  Initialize winsock:
  *  http://msdn.microsoft.com/en-us/library/windows/desktop/ms742213(v=vs.85).aspx
  */
  WSADATA wsaData;
  int wsaErr = WSAStartup(0x101, &wsaData);
  printf("[*] WSAStartup returns: %d\n", wsaErr);
  if (wsaErr != 0) {
    cout << "[x] Could not start WSAStartup. Abort" << endl;
    return -1;
  }

  /*
  *  Initialize the socket
  */
  sockaddr_in local;
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  local.sin_port = htons((u_short) 8080);

  /*
  *  Check and see if we have a valid socket to go on
  */
  SOCKET s;
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s == INVALID_SOCKET) {
    cout << "[x] Invalid socket. Abort" << endl;
    return -1;
  }

  /*
  *  Attempt to bind to the socket
  */
  if (bind(s, (sockaddr*) &local, sizeof(local)) != 0) {
    cout << "[x] Unable to bind. Abort" << endl;
    return -1;
  }

  /*
  *  Start listening
  */
  if (listen(s, 10) != 0) {
    cout << "[x] Unable to listen. Abort" << endl;
    return -1;
  }
  cout << "[*] Listening on port 8080..." << endl;

  SOCKET cli;
  sockaddr_in src;
  int srcLen = sizeof(src);

  while (true) {
    cli = accept(s, (struct sockaddr*) &src, &srcLen);
    int r;

    // Keep recving until the client closes the connection
    do {
      char *recvBuf = (char*) malloc(1024);
      memset(recvBuf, 0x00, 1024);
      r = recv(cli, recvBuf, 1023, 0);

      cout << "Client: " << recvBuf << endl;
      cout << "[*] ACK!" << endl;

      // Send the client something
      char *buf = "hello\n";
      send(cli, buf, strlen(buf), 0);
    } while (r > 0);

    /*
    0 = RECV
    1 = SEND
    2 = BOTH
    */
    shutdown(cli, 2);
    closesocket(cli);
  }

  closesocket(s);
  WSACleanup();

  return 0;
}


#define CHUNK_SIZE 0x190
#define ALLOC_COUNT 10

class SomeObject {
public:
  void function1() {};
  virtual void virtual_function1() {};
};

// Overflow the 2nd chunk
// Corrupt the 3rd chunk
// The fourth chunk is the object we want to read

int prob3(int args, char** argv) {
  int i;
  BSTR bstr;
  BOOL result;
  HANDLE hChunk;
  void* allocations[ALLOC_COUNT];
  BSTR bStrings[5];
  SomeObject* object = new SomeObject();
  HANDLE defaultHeap = GetProcessHeap();
  if (defaultHeap == NULL) {
    printf("No process heap. Are you having a bad day?\n");
    return -1;
  }

  printf("Default heap = 0x%08x\n", defaultHeap);

  // If i is higher than 18, the allocation will be in LFH starting at the 19th chunk
  printf("The following should be all in the backend allocator\n");
  for (i = 0; i < ALLOC_COUNT; i++) {
    hChunk = HeapAlloc(defaultHeap, 0, CHUNK_SIZE);
    memset(hChunk, 'A', CHUNK_SIZE);
    allocations[i] = hChunk;
    printf("[%d] Heap chunk in backend : 0x%08x\n", i, hChunk);
  }

  printf("Freeing allocation at index 3: 0x%08x\n", allocations[3]);
  result = HeapFree(defaultHeap, HEAP_NO_SERIALIZE, allocations[3]);
  if (result == 0) {
    printf("Failed to free\n");
    return -1;
  }

  for (i = 0; i < 5; i++) {
    // Memory look:
    // 014f5b26 42 42 42 42 42 42 42 42 42 42 6c 13 b1  BBBBBBBBBBl..
    // 014f5b33 ed 0a b0 00 08 f8 00 00 00 41 00 41 00  .........A.A.
    // 014f5b40 41 00 41 00 41 00 41 00 41 00 41 00 41  A.A.A.A.A.A.A
    bstr = SysAllocString(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    bStrings[i] = bstr;
    printf("[%d] BSTR string : 0x%08x\n", i, bstr);
  }

  printf("Freeing allocation at index 4 : 0x%08x\n", allocations[4]);
  result = HeapFree(defaultHeap, HEAP_NO_SERIALIZE, allocations[4]);
  if (result == 0) {
    printf("Failed to free\n");
    return -1;
  }

  int objRef = (int) object;
  printf("SomeObject address : 0x%08x\n", objRef);
  printf("Allocating SomeObject to vectors\n");
  vector<int> array1(40, objRef);
  vector<int> array2(40, objRef);
  vector<int> array3(40, objRef);
  vector<int> array4(40, objRef);
  vector<int> array5(40, objRef);
  vector<int> array6(40, objRef);
  vector<int> array7(40, objRef);
  vector<int> array8(40, objRef);
  vector<int> array9(40, objRef);
  vector<int> array10(40, objRef);

  UINT strSize = SysStringByteLen(bStrings[0]);
  printf("Original String size: %d\n", (int) strSize);
  printf("Overflowing allocation 2\n");

  char evilString[] =
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "BBBBBBBBBBBBBBBB"
    "CCCCDDDD"
    "\xff\x00\x00\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00"
    "\x41\x00\x41\x00";
  memcpy(allocations[2], evilString, sizeof(evilString));
  strSize = SysStringByteLen(bStrings[0]);
  printf("Modified String size: %d\n", (int) strSize);

  std::wstring ws(bStrings[0], strSize);
  std::wstring ref = ws.substr(120+16, 4);
  char buf[4];
  memcpy(buf, ref.data(), 4);
  int refAddr = int((unsigned char)(buf[3]) << 24 | (unsigned char)(buf[2]) << 16 | (unsigned char)(buf[1]) << 8 | (unsigned char)(buf[0]));
  memcpy(buf, (void*) refAddr, 4);
  int vftable = int((unsigned char)(buf[3]) << 24 | (unsigned char)(buf[2]) << 16 | (unsigned char)(buf[1]) << 8 | (unsigned char)(buf[0]));
  printf("Found vftable address : 0x%08x\n", vftable);
  int baseAddr = vftable - 0x0003a564;
  printf("====================================\n");
  printf("Image base address is : 0x%08x\n", baseAddr);
  printf("====================================\n");

  system("PAUSE");

  return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Ws2tcpip.h>
#include <Winsock2.h>
#include <stdio.h>
#define DEFAULT_RECV_BUFFER_LEN 1024
#define DEFAULT_FNAME_BUFFER_SIZE 512
#define SERVICE_NAME "Buffer Overflow"
#define SERVICE_DESCRIPTION "Buffer Overflow"
#define PORT 4444

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"advapi32.lib")

LPVOID vulnerableExe = NULL;
DWORD vulnerableExeSize = 0;

SOCKET serverSocket;
struct addrinfo* addrResult;

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;

VOID WINAPI SvcCtrlHandler(DWORD dwCtrl);
VOID SvcInit(DWORD dwArgc, LPTSTR *lpszArgv);
VOID ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv);
VOID AcceptConnection();
VOID StartVulnerableServer();
VOID ReceiveClientMessages(SOCKET clientSocket, SOCKADDR_IN clientInfo);
VOID ClientRequestHandler(SOCKET clientSocket, SOCKADDR_IN clientInfo, PCSTR message);
VOID ReplyClient(SOCKET clientSocket);
LPVOID ReadVulnerableFile(char* fname);


char* GetCurrentPath() {
  // Since we don't know exactly how much data we will get from GetModuleFileNameA,
  // we pre-allocate the buffer with the default size of 512 bytes. If we get an
  // ERROR_INSUFFICIENT_BUFFER, we will just readjust and try again
  LPVOID fnameBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DEFAULT_FNAME_BUFFER_SIZE);
  SIZE_T dwSize = HeapSize(GetProcessHeap(), HEAP_NO_SERIALIZE, fnameBuffer);
  DWORD dwResult = 0;
  unsigned int dwStrLen = 0;

  do {
    dwResult = GetModuleFileNameA(NULL, (LPSTR) fnameBuffer, dwSize);
    dwStrLen = strlen((LPSTR) fnameBuffer);
    if (dwResult == ERROR_INSUFFICIENT_BUFFER) {
      // Damn it, the default buffer size wasn't enough, let's readjust it.
      fnameBuffer = HeapReAlloc(GetProcessHeap(), HEAP_NO_SERIALIZE, fnameBuffer, dwSize + DEFAULT_FNAME_BUFFER_SIZE);
      dwSize = HeapSize(GetProcessHeap(), HEAP_NO_SERIALIZE, fnameBuffer);
    }
  } while (dwResult != dwStrLen);

  return (char*) fnameBuffer;
}

SC_HANDLE InstallSelf() {
  SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (!hScm) {
    printf("- Unable to open a handle for SCManager. Agent will not be installed.\n");
    return NULL;
  }

  char* szPath = GetCurrentPath();
  SC_HANDLE hService = CreateService(
      hScm,                       // hSCManager
      SERVICE_NAME,               // lpServiceName
      SERVICE_NAME,               // lpDisplayName
      SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS,  // dwDesiredAccess
      SERVICE_AUTO_START,         // dwServiceType
      SERVICE_ERROR_NORMAL,       // dwErrorControl
      szPath,                     // lpBinaryPathName
      NULL,                       // lpLoadOrderGroup
      NULL,                       // lpdwTagId
      NULL,                       // lpDependencies
      NULL,                       // lpServiceStartName
      NULL                        // lpPassword
    );

  if (hService == NULL) {
    printf("- Failed to create the service.\n");
    return NULL;
  }

  SC_ACTION scAction;
  scAction.Type = SC_ACTION_RESTART;
  scAction.Delay = 60000; // 1 minute

  SERVICE_FAILURE_ACTIONS fActions;
  fActions.dwResetPeriod = INFINITE;
  fActions.lpRebootMsg = "Restart application";
  fActions.lpCommand = NULL;
  fActions.cActions = 1;
  fActions.lpsaActions = &scAction;

  ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &fActions);

  HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, szPath);
  CloseServiceHandle(hScm);
  return hService;
}


BOOL IsSelfInstalled() {
  BOOL bStatus = FALSE;

  SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (hScm == NULL) {
    // If we fail to OpenSCManager, we have to return TRUE so that we don't try to install
    // the service knowing that it will fail.
    printf("- Unable to open a handle for SCManager\n");
    return TRUE;
  }

  SC_HANDLE hService = OpenService(hScm, SERVICE_NAME, SERVICE_QUERY_STATUS);
  if (hService) {
    // Do "sc delete SERVICE_NAME" if you want to delet the service
    printf("- It looks like the agent has already been installed\n");
    bStatus = TRUE;
    CloseServiceHandle(hService);
  }

  CloseServiceHandle(hScm);

  return bStatus;
}

VOID WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv){
  gSvcStatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, SvcCtrlHandler);
  if (!gSvcStatusHandle){
    printf("- Service failed to start\n");
    return;
  }

  printf("- Service is running\n");

  gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  gSvcStatus.dwServiceSpecificExitCode = 0;
  ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
  SvcInit(dwArgc, lpszArgv);
}

VOID WINAPI SvcCtrlHandler(DWORD dwCtrl){
  switch (dwCtrl){
    case SERVICE_CONTROL_STOP:
      ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
      SetEvent(ghSvcStopEvent);
      ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
      return;
    case SERVICE_CONTROL_INTERROGATE:
      break;
    default:
      break;
  }
}

void SvcInit(DWORD dwArgc, LPTSTR *lpszArgv){
  ghSvcStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (ghSvcStopEvent == NULL){
    ReportSvcStatus(SERVICE_STOPPED, NO_ERROR, 0);
    return;
  }

  ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
  StartVulnerableServer();
}

void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint){
  static DWORD dwCheckPoint = 1;

  gSvcStatus.dwCurrentState = dwCurrentState;
  gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
  gSvcStatus.dwWaitHint = dwWaitHint;

  if (dwCurrentState == SERVICE_START_PENDING)
    gSvcStatus.dwControlsAccepted = 0;
  else
    gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  if (dwCurrentState == SERVICE_RUNNING ||
      dwCurrentState == SERVICE_STOPPED)
    gSvcStatus.dwCheckPoint = 0;
  else
    gSvcStatus.dwCheckPoint = dwCheckPoint++;

  SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

BOOL StartSelf(SC_HANDLE installed){
  return StartService(installed, 0, NULL);
}

struct addrinfo* InitWinsock() {
  printf("- WSAStartup\n");
  WSADATA wsaData;
  int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult !=0 ) {
    return NULL;
  }

  printf("- Translate data to an address structure with getaddrinfo\n");
  struct addrinfo hints;
  ZeroMemory(&hints, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_PASSIVE;
  struct addrinfo *addrResult = NULL;
  iResult = getaddrinfo(NULL, "4444", &hints, &addrResult);
  if (iResult != 0) {
    printf("- getaddrinfo returns: %d\n", iResult);
    WSACleanup();
    return NULL;
  }

  return addrResult;
}

SOCKET CreateSocket(struct addrinfo* addrResult) {
  printf("- Creating a socket\n");
  SOCKET s = socket(addrResult->ai_family, addrResult->ai_socktype, addrResult->ai_protocol);
  if (s == INVALID_SOCKET) {
    freeaddrinfo(addrResult);
    WSACleanup();
    return -1;
  }

  printf("- Binding a socket\n");
  int iResult = bind(s, addrResult->ai_addr, (int) addrResult->ai_addrlen);
  if (iResult == SOCKET_ERROR) {
    freeaddrinfo(addrResult);
    closesocket(s);
    return -1;
  }

  return s;
}

int Listen() {
  printf("- Listening\n");
  int iResult = listen(serverSocket, SOMAXCONN);
  if (iResult == SOCKET_ERROR) {
    return -1;
  }

  return 1;
}

VOID ReplyClient(SOCKET clientSocket)  {
  send(clientSocket, vulnerableExe, vulnerableExeSize, MSG_DONTROUTE);
}


/*
This is the vulnerable function. A classic stack-based buffer overflow.
*/
VOID ClientRequestHandler(SOCKET clientSocket, SOCKADDR_IN clientInfo, PCSTR message) {
  PCSTR ip = inet_ntoa(clientInfo.sin_addr);
  char buffer[1024];
  ZeroMemory(buffer, sizeof(buffer));
  strcat(buffer, "- Client says: ");
  strcat(buffer, message);
  strcat(buffer, "\n");
  printf(buffer);
  ReplyClient(clientSocket);
}

VOID ReceiveClientMessages(SOCKET clientSocket, SOCKADDR_IN clientInfo) {
  char recvBuffer[DEFAULT_RECV_BUFFER_LEN];
  unsigned int recvBufferLen = DEFAULT_RECV_BUFFER_LEN;
  unsigned int bytesRead = 0;
  do {
    // recv() will complete when the input ends with \r\d
    bytesRead = recv(clientSocket, recvBuffer, recvBufferLen, MSG_PEEK);
    if (bytesRead > 0) {
      // Remember to add a null byte terminator, otherwise we will read out-of-bound.
      memcpy(recvBuffer+bytesRead, "\x00", 1);
      ClientRequestHandler(clientSocket, clientInfo, (PCSTR) recvBuffer);
      bytesRead = 0;
    }
  } while (bytesRead > 0);
}

VOID AcceptConnection() {
  printf("- Ready to accept a connection\r\n");
  SOCKADDR_IN clientInfo;
  int clientInfoLen = sizeof(clientInfo);
  SOCKET clientSocket = accept(serverSocket, (SOCKADDR*) &clientInfo, &clientInfoLen);
  PCSTR ip = inet_ntoa(clientInfo.sin_addr);
  if (clientSocket == INVALID_SOCKET) {
    return;
  }

  printf("- Received a connection, handling the messages\n");
  ReceiveClientMessages(clientSocket, clientInfo);

  printf("- Shutting down connection\n");
  int iResult = shutdown(clientSocket, SD_SEND);
  if (iResult == SOCKET_ERROR) {
    closesocket(clientSocket);
  }
}

LPVOID ReadVulnerableFile(char* fname) {
  HANDLE hFile = CreateFileA(fname, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (!hFile) {
    return NULL;
  }
  DWORD dwFileSize = GetFileSize(hFile, NULL);
  vulnerableExeSize = dwFileSize;
  printf("- %s loaded (%d bytes)\n", fname, dwFileSize);
  LPVOID buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
  DWORD dwBytesRead;
  if (!ReadFile(hFile, buffer, dwFileSize, &dwBytesRead, NULL)) {
    HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, buffer);
    CloseHandle(hFile);
    return NULL;
  }

  CloseHandle(hFile);
  return buffer;
}

VOID StartVulnerableServer() {
  char* exePath = GetCurrentPath();
  vulnerableExe = ReadVulnerableFile(exePath);

  struct addrinfo* addrResult = InitWinsock();
  if (!addrResult) {
    printf("- Failed to init Winsock.\n");
    return;
  }

  serverSocket = CreateSocket(addrResult);
  int iResult = Listen();
  if (!iResult) {
    return;
  }

  while (TRUE) {
    AcceptConnection();
  }

  HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, vulnerableExe);
}


#ifdef FOREGROUND_MODE
int main(int argc, char** argv) {
  printf("- In foreground mode\n");
  StartVulnerableServer();
  return 0;
}
#else
int prob4(int argc, char** argv[])
{
  if (!IsSelfInstalled()) {
    printf("- Service not registered on Windows. One will be created.\n");

    SC_HANDLE installed = InstallSelf();
    if (!installed){
      printf("- Failed to create service\n");
      return -1;
    }

    BOOL stat = StartSelf(installed);
    if (!stat){
      printf("- Failed to start service\n");
      return -1;
    }

    CloseServiceHandle(installed);
    return 0;
  }

  printf("- Running the process as a service\n");
  SERVICE_TABLE_ENTRY DispatchTable[] = {
    {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) SvcMain },
    {NULL, NULL},
  };

  if (!StartServiceCtrlDispatcher( DispatchTable )){
    return -1;
  }

  return 0;
}
#endif

#include <Windows.h>
#include <stdio.h>

#define ORIGINAL_STRING_SIZE 1024


int main(int args, char** argv) {
  char originalStr[ORIGINAL_STRING_SIZE];
  memset(originalStr, 'A', ORIGINAL_STRING_SIZE);
  memcpy(originalStr+ORIGINAL_STRING_SIZE-1, "\0", 1);

  WCHAR newBuffer[32];
  memset(newBuffer, '\0', sizeof(newBuffer));
  MultiByteToWideChar(CP_ACP, 0, originalStr, -1, newBuffer, sizeof(newBuffer));
  wprintf(L"%ls\n", newBuffer);
  return 0;
} 
