# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'SAST_Check.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
import ctypes
import re

Final = {}
Read = {}

c_ruleset = {
    "strcpy":
        (
            "Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
            "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused)"
        ),
    "strcpyA" or "strcpyW" or "StrCpy" or "StrCpyA" or "lstrcpyA" or "lstrcpyW" or "_tccpy" or "_mbccpy" or "_ftcscpy" or "_mbsncpy" or "StrCpyN" or "StrCpyNA" or "StrCpyNW" or "StrNCpy" or "strcpynA" or "StrNCpyA" or "StrNCpyW" or "lstrcpynA" or "lstrcpynW":
    # We need more info on these functions; I got their names from the
    # Microsoft "banned" list.  For now, just use "normal" to process them
    # instead of "c_buffer".
        (
            "Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
            "Consider using snprintf, strcpy_s, or strlcpy (warning: strncpy easily misused)"
        ),
    "lstrcpy" or "wcscpy" or "_tcscpy" or "_mbscpy":
        (
            "Does not check for buffer overflows when copying to destination [MS-banned] (CWE-120)",
            "Consider using a function version that stops copying at the end of the buffer"
        ),
    "memcpy" or "CopyMemory" or "bcopy":
        (
            # I've found this to have a lower risk in practice.
            "Does not check for buffer overflows when copying to destination (CWE-120)",
            "Make sure destination can always hold the source data"
        ),
    "strcat":
        (
            "Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
            "Consider using strcat_s, strncat, strlcat, or snprintf (warning: strncat is easily misused)"
        ),
    "lstrcat" or "wcscat" or "_tcscat" or "_mbscat":
        (
            "Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
            ""
        ),
    # TODO: Do more analysis.  Added because they're in MS banned list.
    "StrCat" or "StrCatA" or "StrcatW" or "lstrcatA" or "lstrcatW" or "strCatBuff" or "StrCatBuffA" or "StrCatBuffW" or "StrCatChainW" or "_tccat" or "_mbccat" or "_ftcsat" or "StrCatN" or "StrCatNA" or "StrCatNW" or "StrNCat" or "StrNCatA" or "StrNCatW" or "lstrncat" or "lstrcatnA" or "lstrcatnW":
        (
            "Does not check for buffer overflows when concatenating to destination [MS-banned] (CWE-120)",
            ""
        ),
    "strncpy":
        (
            # Low risk level, because this is often used correctly when FIXING security
            # problems, and raising it to a higher risk level would cause many false
            # positives.
            "Easily used incorrectly; doesn't always \\0-terminate or " +
            "check for invalid pointers [MS-banned] (CWE-120)",
            ""
        ),
    "lstrcpyn" or "wcsncpy" or "_tcsncpy" or "_mbsnbcpy":
        (
            # Low risk level, because this is often used correctly when FIXING security
            # problems, and raising it to a higher risk levle would cause many false
            # positives.
            "Easily used incorrectly; doesn't always \\0-terminate or " +
            "check for invalid pointers [MS-banned] (CWE-120)",
            ""
        ),
    "strncat":
        (
            # Low risk level, because this is often used correctly when
            # FIXING security problems, and raising it to a
            # higher risk level would cause many false positives.
            "Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add) [MS-banned] (CWE-120)",
            "Consider strcat_s, strlcat, snprintf, or automatically resizing strings"
        ),
    "lstrcatn" or "wcsncat" or "_tcsncat" or "_mbsnbcat":
        (
            # Low risk level, because this is often used correctly when FIXING security
            # problems, and raising it to a higher risk level would cause many false
            # positives.
            "Easily used incorrectly (e.g., incorrectly computing the correct maximum size to add) [MS-banned] (CWE-120)",
            "Consider strcat_s, strlcat, or automatically resizing strings"
        ),
    "strccpy" or "strcadd":
        (
            "Subject to buffer overflow if buffer is not as big as claimed (CWE-120)",
            "Ensure that destination buffer is sufficiently large"
        ),
    "char" or "TCHAR" or "wchar_t":
    # This isn't really a function call, but it works.
        (
            "Statically-sized arrays can be improperly restricted, " +
            "leading to potential overflows or other issues (CWE-119!/CWE-120)",
            "Perform bounds checking, use functions that limit length, " +
            "or ensure that the size is larger than the maximum possible length"
        ),

    "gets" or "_getts":
        ("Does not check for buffer overflows (CWE-120, CWE-20)",
         "Use fgets() instead"),

    # The "sprintf" hook will raise "format" issues instead if appropriate:
    "sprintf" or "vsprintf" or "swprintf" or "vswprintf" or "_stprintf" or "_vstprintf":
        (
            "Does not check for buffer overflows (CWE-120)",
            "Use sprintf_s, snprintf, or vsnprintf"
        ),

    "vprintf" or "vwprintf" or "vfwprintf" or "_vtprintf" or "wprintf":
        (
            "If format strings can be influenced by an attacker, they can be exploited (CWE-134)",
            "Use a constant for the format specification"
        ),

    "fprintf" or "vfprintf" or "_ftprintf" or "_vftprintf" or "fwprintf" or "fvwprintf":
        (
            "If format strings can be influenced by an attacker, they can be exploited (CWE-134)",
            "Use a constant for the format specification"
        ),

    # The "syslog" hook will raise "format" issues.
    "syslog":
        (
            "If syslog's format strings can be influenced by an attacker, " +
            "they can be exploited (CWE-134)",
            "Use a constant format string for syslog"
        ),

    "snprintf" or "vsnprintf" or "_snprintf" or "_sntprintf" or "_vsntprintf":
        (
            "If format strings can be influenced by an attacker, they can be " +
            "exploited, and note that sprintf variations do not always \\0-terminate (CWE-134)",
            "Use a constant for the format specification"
        ),

    "scanf" or "vscanf" or "wscanf" or "_tscanf" or "vwscanf":
        (
            "The scanf() family's %s operation, without a limit specification, " +
            "permits buffer overflows (CWE-120, CWE-20)",
            "Specify a limit to %s, or use a different input function"
        ),

    "fscanf" or "sscanf" or "vsscanf" or "vfscanf" or "_ftscanf" or "fwscanf" or "vfwscanf" or "vswscanf":
        (
            "The scanf() family's %s operation, without a limit specification, " +
            "permits buffer overflows (CWE-120, CWE-20)",
            "Specify a limit to %s, or use a different input function"
        ),

    "strlen" or "wcslen" or "_tcslen" or "_mbslen":
        (
            # Often this isn't really a risk, and even when it is, at worst it
            # often causes a program crash (and nothing worse).
            "Does not handle strings that are not \\0-terminated; " +
            "if given one it may perform an over-read (it could cause a crash " +
            "if unprotected) (CWE-126)",
            ""
        ),

    "MultiByteToWideChar":  # Windows
        (
            # Only the default - this will be changed in many cases.
            "Requires maximum length in CHARACTERS, not bytes (CWE-120)",
            ""
        ),

    "streadd" or "strecpy":
        (
            "This function does not protect against buffer overflows (CWE-120)",
            "Ensure the destination has 4 times the size of the source, to leave room for expansion"
        ),

    "strtrns":
        (
            "This function does not protect against buffer overflows (CWE-120)",
            "Ensure that destination is at least as long as the source"
        ),

    "realpath":
        (
            "This function does not protect against buffer overflows, " +
            "and some implementations can overflow internally (CWE-120/CWE-785!)",
            "Ensure that the destination buffer is at least of size MAXPATHLEN, and" +
            "to protect against implementation problems, the input argument " +
            "should also be checked to ensure it is no larger than MAXPATHLEN"
        ),

    "getopt" or "getopt_long":
        (
            "Some older implementations do not protect against internal buffer overflows (CWE-120, CWE-20)",
            "Check implementation on installation, or limit the size of all string inputs"
        ),

    "getwd":
        (
            "This does not protect against buffer overflows " +
            "by itself, so use with caution (CWE-120, CWE-20)",
            "Use getcwd instead"
        ),

    # fread not included here; in practice I think it's rare to mistake it.
    "getchar" or "fgetc" or "getc" or "read" or "_gettc":
        (
            "Check buffer boundaries if used in a loop including recursive loops (CWE-120, CWE-20)",
            ""
        ),

    "access":
    # ???: TODO: analyze TOCTOU more carefully.
        (
            "This usually indicates a security flaw.  If an " +
            "attacker can change anything along the path between the " +
            "call to access() and the file's actual use (e.g., by moving " +
            "files), the attacker can exploit the race condition (CWE-362/CWE-367!)",
            "Set up the correct permissions (e.g., using setuid()) and " +
            "try to open the file directly"
        ),
    "chown":
        (
            "This accepts filename arguments; if an attacker " +
            "can move those files, a race condition results. (CWE-362)",
            "Use fchown( ) instead"
        ),
    "chgrp":
        (
            "This accepts filename arguments; if an attacker " +
            "can move those files, a race condition results. (CWE-362)",
            "Use fchgrp( ) instead"
        ),
    "chmod":
        (
            "This accepts filename arguments; if an attacker " +
            "can move those files, a race condition results. (CWE-362)",
            "Use fchmod( ) instead"
        ),
    "vfork":
        (
            "On some old systems, vfork() permits race conditions, and it's " +
            "very difficult to use correctly (CWE-362)",
            "Use fork() instead"
        ),
    "readlink":
        (
            "This accepts filename arguments; if an attacker " +
            "can move those files or change the link content, " +
            "a race condition results.  " +
            "Also, it does not terminate with ASCII NUL. (CWE-362, CWE-20)",
            # This is often just a bad idea, and it's hard to suggest a
            # simple alternative:
            "Reconsider approach"
        ),

    "tmpfile":
        (
            "Function tmpfile() has a security flaw on some systems (e.g., older System V systems) (CWE-377)",
            ""
        ),
    "tmpnam" or "tempnam":
        (
            "Temporary file race condition (CWE-377)",
            ""
        ),

    # TODO: Detect GNOME approach to mktemp and ignore it.
    "mktemp":
        (
            "Temporary file race condition (CWE-377)",
            ""
        ),

    "mkstemp":
        (
            "Potential for temporary file vulnerability in some circumstances.  Some older Unix-like systems create temp files with permission to write by all by default, so be sure to set the umask to override this. Also, some older Unix systems might fail to use O_EXCL when opening the file, so make sure that O_EXCL is used by the library (CWE-377)",
            ""
        ),

    "fopen" or "open":
        (
            "Check when opening files - can an attacker redirect it (via symlinks), force the opening of special file type (e.g., device files), move things around to create a race condition, control its ancestors, or change its contents? (CWE-362)",
            ""
        ),

    "umask":
        (
            "Ensure that umask is given most restrictive possible setting (e.g., 066 or 077) (CWE-732)",
            ""
        ),

    # Windows.  TODO: Detect correct usage approaches and ignore it.
    "GetTempFileName":
        (
            "Temporary file race condition in certain cases " +
            "(e.g., if run as SYSTEM in many versions of Windows) (CWE-377)",
            ""
        ),

    # TODO: Need to detect varying levels of danger.
    "execl" or "execlp" or "execle" or "execv" or "execvp" or "system" or "popen" or "WinExec" or "ShellExecute":
        (
            "This causes a new program to execute and is difficult to use safely (CWE-78)",
            "try using a library call that implements the same functionality " +
            "if available"
        ),

    # TODO: Be more specific.  The biggest problem involves "first" param NULL,
    # second param with embedded space. Windows.
    "CreateProcessAsUser" or "CreateProcessWithLogon":
        (
            "This causes a new process to execute and is difficult to use safely (CWE-78)",
            "Especially watch out for embedded spaces"
        ),

    # TODO: Be more specific.  The biggest problem involves "first" param NULL,
    # second param with embedded space. Windows.
    "CreateProcess":
        (
            "This causes a new process to execute and is difficult to use safely (CWE-78)",
            "Specify the application path in the first argument, NOT as part of the second, " +
            "or embedded spaces could allow an attacker to force a different program to run"
        ),

    "atoi" or "atol" or "_wtoi" or "_wtoi64":
        (
            "Unless checked, the resulting number can exceed the expected range " +
            "(CWE-190)",
            "If source untrusted, check both minimum and maximum, even if the" +
            " input had no minus sign (large numbers can roll over into negative" +
            " number; consider saving to an unsigned value if that is intended)"
        ),

    # Random values.  Don't trigger on "initstate", it's too common a term.
    "drand48" or "erand48" or "jrand48" or "lcong48" or "lrand48" or "mrand48" or "nrand48" or "random" or "seed48" or "setstate" or "srand" or "strfry" or "srandom" or "g_rand_boolean" or "g_rand_int" or "g_rand_int_range" or "g_rand_double" or "g_rand_double_range" or "g_random_boolean" or "g_random_int" or "g_random_int_range" or "g_random_double" or "g_random_double_range":
        (
            "This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327)",
            "Use a more secure technique for acquiring random values"
        ),

    "crypt":
        (
            "Function crypt is a poor one-way hashing algorithm; " +
            "since it only accepts passwords of 8 characters or less, " +
            "and only a two-byte salt, it is excessively vulnerable to " +
            "dictionary attacks given today's faster computing equipment (CWE-327)",
            "Use a different algorithm, such as SHA-256, with a larger " +
            "non-repeating salt"
        ),

    # OpenSSL EVP calls to use DES.
    "EVP_des_ecb" or "EVP_des_cbc" or "EVP_des_cfb" or "EVP_des_ofb" or "EVP_desx_cbc":
        (
            "DES only supports a 56-bit keysize, which is too small given today's computers (CWE-327)",
            "Use a different patent-free encryption algorithm with a larger keysize, " +
            "such as 3DES or AES"
        ),

    # Other OpenSSL EVP calls to use small keys.
    "EVP_rc4_40" or "EVP_rc2_40_cbc" or "EVP_rc2_64_cbc":
        (
            "These keysizes are too small given today's computers (CWE-327)",
            "Use a different patent-free encryption algorithm with a larger keysize, " +
            "such as 3DES or AES"
        ),

    "chroot":
        (
            "chroot can be very helpful, but is hard to use correctly (CWE-250, CWE-22)",
            "Make sure the program immediately chdir(\"/\")," +
            " closes file descriptors," +
            " and drops root privileges, and that all necessary files" +
            " (and no more!) are in the new root"
        ),

    "getenv" or "curl_getenv":
        ("Environment variables are untrustable input if they can be" +
         " set by an attacker.  They can have any content and" +
         " length, and the same variable can be set more than once (CWE-807, CWE-20)",
         "Check environment variables carefully before using them"
         ),

    "g_get_home_dir":
        ("This function is synonymous with 'getenv(\"HOME\")';" +
         "it returns untrustable input if the environment can be" +
         "set by an attacker.  It can have any content and length, " +
         "and the same variable can be set more than once (CWE-807, CWE-20)",
         "Check environment variables carefully before using them"
         ),

    "g_get_tmp_dir":
        ("This function is synonymous with 'getenv(\"TMP\")';" +
         "it returns untrustable input if the environment can be" +
         "set by an attacker.  It can have any content and length, " +
         "and the same variable can be set more than once (CWE-807, CWE-20)",
         "Check environment variables carefully before using them"
         ),

    # These are Windows-unique:

    # TODO: Should have lower risk if the program checks return value.
    "RpcImpersonateClient" or "ImpersonateLoggedOnUser" or "CoImpersonateClient" or "" +
                                                                                    "ImpersonateNamedPipeClient" or "ImpersonateDdeClientWindow" or "ImpersonateSecurityContext" or "" +
                                                                                                                                                                                    "SetThreadToken":
        ("If this call fails, the program could fail to drop heightened privileges (CWE-250)",
         "Make sure the return value is checked, and do not continue if a failure is reported"
         ),

    "InitializeCriticalSection":
        ("Exceptions can be thrown in low-memory situations",
         "Use InitializeCriticalSectionAndSpinCount instead"
         ),

    "EnterCriticalSection":
        ("On some versions of Windows, exceptions can be thrown in low-memory situations",
         "Use InitializeCriticalSectionAndSpinCount instead"
         ),

    "LoadLibrary" or "LoadLibraryEx":
        ("Ensure that the full path to the library is specified, or current directory may be used (CWE-829, CWE-20)",
         "Use registry entry or GetWindowsDirectory to find library path, if you aren't already"
         ),

    "SetSecurityDescriptorDacl":
        (
            "Never create NULL ACLs; an attacker can set it to Everyone (Deny All Access), " +
            "which would even forbid administrator access (CWE-732)",
            ""
        ),

    "AddAccessAllowedAce":
        (
            "This doesn't set the inheritance bits in the access control entry (ACE) header (CWE-732)",
            "Make sure that you set inheritance by hand if you wish it to inherit"
        ),

    "getlogin":
        (
            "It's often easy to fool getlogin.  Sometimes it does not work at all, because some program messed up the utmp file.  Often, it gives only the first 8 characters of the login name. The user currently logged in on the controlling tty of our program need not be the user who started it.  Avoid getlogin() for security-related purposes (CWE-807)",
            "Use getpwuid(geteuid()) and extract the desired information instead"
        ),

    "cuserid":
        (
            "Exactly what cuserid() does is poorly defined (e.g., some systems use the effective uid, like Linux, while others like System V use the real uid). Thus, you can't trust what it does. It's certainly not portable (The cuserid function was included in the 1988 version of POSIX, but removed from the 1990 version).  Also, if passed a non-null parameter, there's a risk of a buffer overflow if the passed-in buffer is not at least L_cuserid characters long (CWE-120)",
            "Use getpwuid(geteuid()) and extract the desired information instead"
        ),

    "getpw":
        (
            "This function is dangerous; it may overflow the provided buffer. It extracts data from a 'protected' area, but most systems have many commands to let users modify the protected area, and it's not always clear what their limits are.  Best to avoid using this function altogether (CWE-676, CWE-120)",
            "Use getpwuid() instead"
        ),

    "getpass":
        (
            "This function is obsolete and not portable. It was in SUSv2 but removed by POSIX.2.  What it does exactly varies considerably between systems, particularly in where its prompt is displayed and where it gets its data (e.g., /dev/tty, stdin, stderr, etc.). In addition, some implementations overflow buffers. (CWE-676, CWE-120, CWE-20)",
            "Make the specific calls to do exactly what you want.  If you continue to use it, or write your own, be sure to zero the password as soon as possible to avoid leaving the cleartext password visible in the process' address space"
        ),

    "gsignal" or "ssignal":
        (
            "These functions are considered obsolete on most systems, and very non-poertable (Linux-based systems handle them radically different, basically if gsignal/ssignal were the same as raise/signal respectively, while System V considers them a separate set and obsolete) (CWE-676)",
            "Switch to raise/signal, or some other signalling approach"
        ),

    "memalign":
        (
            "On some systems (though not Linux-based systems) an attempt to free() results from memalign() may fail. This may, on a few systems, be exploitable.  Also note that memalign() may not check that the boundary parameter is correct (CWE-676)",
            "Use posix_memalign instead (defined in POSIX's 1003.1d).  Don't switch to valloc(); it is marked as obsolete in BSD 4.3, as legacy in SUSv2, and is no longer defined in SUSv3.  In some cases, malloc()'s alignment may be sufficient"
        ),

    "ulimit":
        (
            "This C routine is considered obsolete (as opposed to the shell command by the same name, which is NOT obsolete) (CWE-676)",
            "Use getrlimit(2), setrlimit(2), and sysconf(3) instead"
        ),

    "usleep":
        (
            "This C routine is considered obsolete (as opposed to the shell command by the same name).   The interaction of this function with SIGALRM and other timer functions such as sleep(), alarm(), setitimer(), and nanosleep() is unspecified (CWE-676)",
            "Use nanosleep(2) or setitimer(2) instead"
        ),

    # Input functions, useful for -I
    "recv" or "recvfrom" or "recvmsg" or "fread" or "readv":
        ("Function accepts input from outside program (CWE-20)",
         "Make sure input data is filtered, especially if an attacker could manipulate it"
         )

    # TODO: detect C++'s:   cin >> charbuf, where charbuf is a char array; the problem
    #       is that flawfinder doesn't have type information, and ">>" is safe with
    #       many other types.
    # ("send" and friends aren't todo, because they send out.. not input.)
    # TODO: cwd("..") in user's space - TOCTOU vulnerability
    # TODO: There are many more rules to add, esp. for TOCTOU.
}


def scanning(line, data, rule):
    result = []
    for r in rule:  # 예) 한 줄 읽어옴.

        d = re.compile(r + '\(.*?\)')
        find = d.findall(data)
        if (find):
            data = data.replace(r, "")
            # print(line,r)
            result.append(r)

    Final[line] = result


def quote(data):
    quote = re.compile('(\".*?\"|\'.*?\')')

    if (quote.findall(data)):  # find quote
        str = quote.findall(data)

        for i in str:  # "" 제거
            data = data.replace(i, "")
    return data


def _start(path):
    f = open(path, "rb")
    LN = 1
    while True:

        line = f.readline().decode('utf-8').replace(" ", "")

        data = quote(line)  # 문자열 제거

        scanning(LN, data, c_ruleset)

        if (Final[LN] != []):
            Read[LN] = [line.replace("\n", ""), ]

        LN += 1

        if not line: break

    f.close()

class Ui_CheckWindow(object):
    def setupUi(self, CheckWindow):
        CheckWindow.setObjectName("CheckWindow")
        CheckWindow.resize(1100, 900)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap("Icon.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        CheckWindow.setWindowIcon(icon)
        myappid = 'mycompany.myproduct.subproduct.version'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        self.centralwidget = QtWidgets.QWidget(CheckWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.textBrowser_2 = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_2.setGeometry(QtCore.QRect(720, 39, 350, 180))
        self.textBrowser_2.setObjectName("textBrowser_2")
        self.textBrowser_3 = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_3.setGeometry(QtCore.QRect(720, 262, 350, 180))
        self.textBrowser_3.setObjectName("textBrowser_3")
        self.textBrowser_4 = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser_4.setGeometry(QtCore.QRect(720, 486, 350, 180))
        self.textBrowser_4.setObjectName("textBrowser_4")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(28, 16, 671, 601))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.textEdit = QtWidgets.QTextEdit(self.tab)
        self.textEdit.setGeometry(QtCore.QRect(-3, -4, 671, 581))
        self.textEdit.setObjectName("textEdit")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.textBrowser = QtWidgets.QTextBrowser(self.tab_2)
        self.textBrowser.setGeometry(QtCore.QRect(-5, -2, 671, 581))
        self.textBrowser.setObjectName("textBrowser")
        self.tabWidget.addTab(self.tab_2, "")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(720, 19, 64, 15))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(720, 242, 64, 15))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(720, 466, 64, 15))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(30, 628, 111, 16))
        self.label_4.setObjectName("label_4")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(730, 699, 150, 60))
        font = QtGui.QFont()
        font.setFamily("맑은 고딕")
        font.setPointSize(10)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(910, 699, 150, 60))
        font = QtGui.QFont()
        font.setFamily("맑은 고딕")
        font.setPointSize(10)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(730, 781, 150, 60))
        font = QtGui.QFont()
        font.setFamily("맑은 고딕")
        font.setPointSize(10)
        self.pushButton_3.setFont(font)
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(910, 781, 150, 60))
        font = QtGui.QFont()
        font.setFamily("맑은 고딕")
        font.setPointSize(10)
        self.pushButton_4.setFont(font)
        self.pushButton_4.setObjectName("pushButton_4")
        self.tableWidget = QtWidgets.QTableWidget(self.centralwidget)
        self.tableWidget.setGeometry(QtCore.QRect(30, 650, 671, 192))
        self.tableWidget.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidget.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.tableWidget.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(3)
        self.tableWidget.setColumnWidth(0, 110)
        self.tableWidget.setColumnWidth(1, 410)
        self.tableWidget.setColumnWidth(2, 100)
        self.tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget.setHorizontalHeaderItem(2, item)
        CheckWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(CheckWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1100, 26))
        self.menubar.setObjectName("menubar")
        CheckWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(CheckWindow)
        self.statusbar.setObjectName("statusbar")
        CheckWindow.setStatusBar(self.statusbar)

        self.retranslateUi(CheckWindow)
        self.tabWidget.setCurrentIndex(0)
        self.pushButton.clicked.connect(self.Check_slot1)
        self.pushButton_2.clicked.connect(self.Check_slot2)
        self.pushButton_3.clicked.connect(self.Check_slot3)
        self.pushButton_4.clicked.connect(self.Check_slot4)
        self.tableWidget.itemDoubleClicked['QTableWidgetItem*'].connect(self.Check_list_clicked1)
        QtCore.QMetaObject.connectSlotsByName(CheckWindow)

        self.pushButton_2.setVisible(False)
        self.pushButton_3.setVisible(False)
        self.pushButton_4.setVisible(False)

    def Check_slot1(self):
        global Read
        global Final
        Read = dict()
        Final = dict()

        path = self.textEdit.toPlainText()
        path = path.replace("file:///","")
        _start(path)

        self.textEdit.clear()
        while self.tableWidget.rowCount() > 0:
            self.tableWidget.removeRow(0);

        for i in Read:
            str1 = ""
            row_number = 0
            self.tableWidget.insertRow(row_number)
            self.tableWidget.setItem(row_number, 0, QtWidgets.QTableWidgetItem(str(i)))
            self.tableWidget.setItem(row_number, 1, QtWidgets.QTableWidgetItem(Read[i][0]))
            for j in Final[i]:
                str1 += j+" "
            self.tableWidget.setItem(row_number, 2, QtWidgets.QTableWidgetItem(str1))
            row_number += 1


        self.pushButton_2.setVisible(True)
        self.pushButton_3.setVisible(True)
        self.pushButton_4.setVisible(True)

    def Check_slot2(self):
        pass

    def Check_slot3(self):
        pass

    def Check_slot4(self):
        pass

    def Check_list_clicked1(self, clickedIndex):
        row = clickedIndex.row()
        item1 = self.tableWidget.item(row, 0)
        item2 = self.tableWidget.item(row, 1)
        item3 = self.tableWidget.item(row, 2)

        t=item3.text().replace(" ","")

        self.textBrowser_2.clear()
        self.textBrowser_3.clear()
        self.textBrowser_4.clear()

        self.textBrowser_2.append(t)
        self.textBrowser_2.append(c_ruleset[t][0])
        self.textBrowser_3.append(c_ruleset[t][1])
        self.textBrowser_4.append("https://stackoverflow.com/search?q="+t)


    def retranslateUi(self, CheckWindow):
        _translate = QtCore.QCoreApplication.translate
        CheckWindow.setWindowTitle(_translate("CheckWindow", "SAST [검사결과]"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("CheckWindow", "소스코드 입력"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("CheckWindow", "파일 업로드"))
        self.label.setText(_translate("CheckWindow", "취약점"))
        self.label_2.setText(_translate("CheckWindow", "보안방안"))
        self.label_3.setText(_translate("CheckWindow", "참고자료"))
        self.label_4.setText(_translate("CheckWindow", "취약점 리스트"))
        self.pushButton.setText(_translate("CheckWindow", "검사"))
        self.pushButton_2.setText(_translate("CheckWindow", "TXT"))
        self.pushButton_3.setText(_translate("CheckWindow", "HTML"))
        self.pushButton_4.setText(_translate("CheckWindow", "PushButton"))
        item = self.tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("CheckWindow", "라인"))
        item = self.tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("CheckWindow", "취약한 코드"))
        item = self.tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("CheckWindow", "취약명"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    CheckWindow = QtWidgets.QMainWindow()
    ui = Ui_CheckWindow()
    ui.setupUi(CheckWindow)
    CheckWindow.show()
    sys.exit(app.exec_())

