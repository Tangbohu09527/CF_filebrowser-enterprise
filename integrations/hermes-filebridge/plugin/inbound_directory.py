"""Create a private random task directory under an operator-owned root.

No caller-controlled filename, ACL repair, chmod emulation, or directory removal.
The native worker independently validates/locks the returned directory at use.
"""
from contextlib import contextmanager
import os
import re
import secrets
import stat
import sys

from .inbound import BridgeError


def _failure():
    return BridgeError("task_directory_unavailable")


def _valid_root(root):
    if (not isinstance(root, str) or not root or "\0" in root
            or not os.path.isabs(root) or os.path.normpath(root) != root):
        return False
    if os.name == "nt":
        if not re.match(r"^[A-Za-z]:\\", root) or len(root) <= 3 or "/" in root or ":" in root[2:]:
            return False
        for component in root[3:].split("\\"):
            if (not component or component.rstrip(". ") != component
                    or re.search(r'[<>"|?*\x00-\x1f]', component)
                    or re.fullmatch(r"CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]", component.split(".")[0], re.I)):
                return False
        return True
    return root != "/" and not root.startswith("//")


class _Windows:
    def __init__(self):
        import ctypes as c
        from ctypes import wintypes as w
        self.c, self.w = c, w
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.advapi = c.WinDLL("advapi32", use_last_error=True)

        class Attributes(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", w.LPVOID), ("inherit", w.BOOL)]

        class FileInfo(c.Structure):
            _fields_ = [("attributes", w.DWORD), ("creation", w.FILETIME),
                        ("access", w.FILETIME), ("write", w.FILETIME), ("volume", w.DWORD),
                        ("size_high", w.DWORD), ("size_low", w.DWORD), ("links", w.DWORD),
                        ("index_high", w.DWORD), ("index_low", w.DWORD)]

        self.Attributes, self.FileInfo = Attributes, FileInfo

        def api(library, name, result, *args):
            function = getattr(library, name)
            function.restype, function.argtypes = result, list(args)
            return function

        self.create_file = api(self.kernel, "CreateFileW", w.HANDLE, w.LPCWSTR, w.DWORD, w.DWORD,
                               w.LPVOID, w.DWORD, w.DWORD, w.HANDLE)
        self.create_directory = api(self.kernel, "CreateDirectoryW", w.BOOL, w.LPCWSTR, c.POINTER(Attributes))
        self.close = api(self.kernel, "CloseHandle", w.BOOL, w.HANDLE)
        self.info = api(self.kernel, "GetFileInformationByHandle", w.BOOL, w.HANDLE, c.POINTER(FileInfo))
        self.volume = api(self.kernel, "GetVolumeInformationByHandleW", w.BOOL, w.HANDLE,
                          w.LPWSTR, w.DWORD, w.LPVOID, w.LPVOID, w.LPVOID, w.LPWSTR, w.DWORD)
        self.drive_type = api(self.kernel, "GetDriveTypeW", w.UINT, w.LPCWSTR)
        self.free = api(self.kernel, "LocalFree", w.LPVOID, w.LPVOID)
        self.process = api(self.kernel, "GetCurrentProcess", w.HANDLE)
        self.open_token = api(self.advapi, "OpenProcessToken", w.BOOL, w.HANDLE, w.DWORD, c.POINTER(w.HANDLE))
        self.token_info = api(self.advapi, "GetTokenInformation", w.BOOL, w.HANDLE, c.c_int,
                              w.LPVOID, w.DWORD, c.POINTER(w.DWORD))
        self.sid_string = api(self.advapi, "ConvertSidToStringSidW", w.BOOL, w.LPVOID, c.POINTER(w.LPWSTR))
        self.valid_sid = api(self.advapi, "IsValidSid", w.BOOL, w.LPVOID)
        self.security = api(self.advapi, "GetSecurityInfo", w.DWORD, w.HANDLE, c.c_int, w.DWORD,
                            c.POINTER(w.LPVOID), w.LPVOID, c.POINTER(w.LPVOID), w.LPVOID, c.POINTER(w.LPVOID))
        self.control = api(self.advapi, "GetSecurityDescriptorControl", w.BOOL, w.LPVOID,
                           c.POINTER(w.WORD), c.POINTER(w.DWORD))
        self.get_ace = api(self.advapi, "GetAce", w.BOOL, w.LPVOID, w.DWORD, c.POINTER(w.LPVOID))
        self.sddl = api(self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", w.BOOL,
                        w.LPCWSTR, w.DWORD, c.POINTER(w.LPVOID), w.LPVOID)

    def sid(self, pointer):
        value = self.w.LPWSTR()
        if not pointer or not self.valid_sid(pointer) or not self.sid_string(pointer, self.c.byref(value)):
            raise _failure()
        try:
            return value.value
        finally:
            self.free(self.c.cast(value, self.w.LPVOID))

    def current_sid(self):
        token = self.w.HANDLE()
        if not self.open_token(self.process(), 0x8, self.c.byref(token)):
            raise _failure()
        try:
            needed = self.w.DWORD()
            self.token_info(token, 1, None, 0, self.c.byref(needed))
            if needed.value < self.c.sizeof(self.w.LPVOID) or needed.value > 65536:
                raise _failure()
            buffer = self.c.create_string_buffer(needed.value)
            if not self.token_info(token, 1, buffer, needed, self.c.byref(needed)):
                raise _failure()
            return self.sid(self.w.LPVOID.from_buffer(buffer).value)
        finally:
            self.close(token)

    def identity(self, handle):
        info = self.FileInfo()
        if not self.info(handle, self.c.byref(info)) or info.attributes & 0x400 or not info.attributes & 0x10:
            raise _failure()
        return info.volume, info.index_high, info.index_low

    def lock(self, path):
        # A metadata-only handle does NOT block rename. LIST_DIRECTORY is
        # essential, along with omitting FILE_SHARE_DELETE.
        handle = self.create_file(path, 0x20000 | 0x80 | 0x1, 0x1 | 0x2,
                                  None, 3, 0x02000000 | 0x00200000, None)
        if handle in (None, self.c.c_void_p(-1).value):
            raise _failure()
        try:
            self.identity(handle)
        except Exception:
            self.close(handle)
            raise
        return handle

    def private_acl(self, handle, current_sid):
        owner, dacl, descriptor = self.w.LPVOID(), self.w.LPVOID(), self.w.LPVOID()
        if self.security(handle, 1, 0x1 | 0x4, self.c.byref(owner), None,
                         self.c.byref(dacl), None, self.c.byref(descriptor)) != 0:
            raise _failure()
        try:
            flags, revision = self.w.WORD(), self.w.DWORD()
            if (self.sid(owner) != current_sid or not dacl
                    or not self.control(descriptor, self.c.byref(flags), self.c.byref(revision))
                    or not flags.value & 0x1000):
                raise _failure()
            count = self.c.c_ushort.from_address(dacl.value + 4).value
            if not count:
                raise _failure()
            for index in range(count):
                ace = self.w.LPVOID()
                if not self.get_ace(dacl, index, self.c.byref(ace)) or not ace:
                    raise _failure()
                header = self.c.string_at(ace, 8)
                if (header[0] != 0 or int.from_bytes(header[2:4], "little") < 16
                        or self.sid(ace.value + 8) not in {current_sid, "S-1-5-18", "S-1-5-32-544"}):
                    raise _failure()
        finally:
            self.free(descriptor)

    def create(self, path, current_sid):
        descriptor = self.w.LPVOID()
        sddl = f"O:{current_sid}D:P(A;OICI;FA;;;{current_sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        if not self.sddl(sddl, 1, self.c.byref(descriptor), None):
            raise _failure()
        try:
            attributes = self.Attributes(self.c.sizeof(self.Attributes), descriptor, False)
            if not self.create_directory(path, self.c.byref(attributes)):
                if self.c.get_last_error() == 183:
                    raise FileExistsError()
                raise _failure()
        finally:
            self.free(descriptor)


@contextmanager
def _windows_root(root):
    api = _Windows()
    handles = []
    try:
        if api.drive_type(root[:3]) not in (2, 3, 6):
            raise _failure()
        current = root[:3]
        for component in [None, *root[3:].split("\\")]:
            if component is not None:
                current = os.path.join(current, component)
            handle = api.lock(current)
            try:
                identity = api.identity(handle)
            except Exception:
                api.close(handle)
                raise
            handles.append((handle, identity))
        filesystem = api.c.create_unicode_buffer(32)
        if (not api.volume(handles[-1][0], None, 0, None, None, None, filesystem, len(filesystem))
                or filesystem.value != "NTFS"):
            raise _failure()
        sid = api.current_sid()
        api.private_acl(handles[-1][0], sid)
        yield api, handles, sid
    finally:
        for handle, _identity in reversed(handles):
            api.close(handle)


def _create_windows(root):
    with _windows_root(root) as (api, handles, sid):
        for _attempt in range(4):
            path = os.path.join(root, "task-" + secrets.token_hex(16))
            try:
                api.create(path, sid)
            except FileExistsError:
                continue
            child = api.lock(path)
            try:
                api.private_acl(child, sid)
                for handle, identity in handles:
                    if api.identity(handle) != identity:
                        raise _failure()
                api.private_acl(handles[-1][0], sid)
                return path
            finally:
                api.close(child)
    raise _failure()


def _create_linux(root):
    handles = []
    paths = []
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        handle = os.open("/", flags)
        handles.append(handle)
        paths.append("/")
        for component in root[1:].split("/"):
            handle = os.open(component, flags, dir_fd=handle)
            handles.append(handle)
            paths.append(os.path.join(paths[-1], component))
        authorized = os.fstat(handle)
        if authorized.st_uid != os.geteuid() or stat.S_IMODE(authorized.st_mode) != 0o700:
            raise _failure()
        for _attempt in range(4):
            name = "task-" + secrets.token_hex(16)
            try:
                os.mkdir(name, 0o700, dir_fd=handle)
            except FileExistsError:
                continue
            child = os.open(name, flags, dir_fd=handle)
            try:
                info = os.fstat(child)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise _failure()
                for selected, path in zip(handles, paths):
                    if not os.path.samestat(os.fstat(selected), os.stat(path, follow_symlinks=False)):
                        raise _failure()
                if not os.path.samestat(info, os.stat(name, dir_fd=handle, follow_symlinks=False)):
                    raise _failure()
                checked_root = os.fstat(handle)
                if checked_root.st_uid != os.geteuid() or stat.S_IMODE(checked_root.st_mode) != 0o700:
                    raise _failure()
                return os.path.join(root, name)
            finally:
                os.close(child)
    finally:
        for handle in reversed(handles):
            os.close(handle)
    raise _failure()


def create_task_directory(root: str) -> str:
    """Create only a new random child, or raise a fixed non-sensitive error.

    A failed post-create verification may leave an empty private directory for
    operator inspection; this API never guesses which path is safe to delete.
    """
    try:
        if not _valid_root(root):
            raise _failure()
        if os.name == "nt":
            return _create_windows(root)
        if sys.platform.startswith("linux"):
            return _create_linux(root)
        raise _failure()
    except Exception:
        raise _failure() from None
