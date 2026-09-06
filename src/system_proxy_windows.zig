//! system_proxy_windows — Windows 系统代理平台实现（#79）
//!
//! 系统代理：wininet.dll InternetSetOptionW（动态加载，zf.win_dll 模式；
//! 结构体/常量照抄 sing/common/wininet/wininet_windows.go）。wininet 不支持
//! 系统级 SOCKS，support_socks 忽略（上游同语义）。
//! env 注入：setx 写 HKCU\Environment 用户环境变量（大小写不敏感，设小写）。
//!   注意：setx 只影响新进程、1024 字符上限（proxy 值短，够用）。
//!
//! 错误语义：wininet 失败 → diag 填 GetLastError 数字 → return error.EnableFailed；
//! env 注入（setx）失败仅 append 诊断（软约束）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const common = @import("system_proxy_common.zig");

const ProxyError = common.ProxyError;
const Diag = common.Diag;

const is_windows = builtin.os.tag == .windows;

extern "c" fn system(command: [*:0]const u8) c_int;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;

// 常量照抄 sing/common/wininet/wininet_windows.go（不猜值）
const INTERNET_OPTION_PER_CONNECTION_OPTION: u32 = 75;
const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
const INTERNET_OPTION_REFRESH: u32 = 37;
const INTERNET_OPTION_PROXY_SETTINGS_CHANGED: u32 = 95;

const INTERNET_PER_CONN_FLAGS: u32 = 1;
const INTERNET_PER_CONN_PROXY_SERVER: u32 = 2;

const PROXY_TYPE_DIRECT: u32 = 1;
const PROXY_TYPE_PROXY: u32 = 2;
const PROXY_TYPE_AUTO_DETECT: u32 = 8;

/// 布局照抄 Go internetPerConnOption{dwOption uint32; value uint64}
const InternetPerConnOption = extern struct {
    dw_option: u32,
    value: u64 = 0,
};

/// 布局照抄 Go internetPerConnOptionList
const InternetPerConnOptionList = extern struct {
    dw_size: u32,
    psz_connection: ?*const anyopaque = null,
    dw_option_count: u32,
    dw_option_error: u32 = 0,
    p_options: [*]const InternetPerConnOption,
};

fn internetSetOptionW(option: u32, buf: ?*const anyopaque, size: u32) bool {
    if (comptime !is_windows) return false;
    const handle = zf.win_dll.load("wininet.dll") orelse return false;
    const proc_ptr = zf.win_dll.proc(handle, "InternetSetOptionW") orelse return false;
    const F = *const fn (?*anyopaque, u32, ?*anyopaque, u32) callconv(.winapi) i32;
    const f: F = @ptrCast(@alignCast(proc_ptr));
    return f(null, option, @constCast(buf), size) == 1;
}

/// 设置序列（照抄 setOptions）：PerConnectionOption → SettingsChanged
/// → ProxySettingsChanged → Refresh。
fn setPerConnOptions(options: []const InternetPerConnOption) bool {
    var list = InternetPerConnOptionList{
        .dw_size = @sizeOf(InternetPerConnOptionList),
        .dw_option_count = @intCast(options.len),
        .p_options = options.ptr,
    };
    if (!internetSetOptionW(INTERNET_OPTION_PER_CONNECTION_OPTION, &list, list.dw_size)) return false;
    if (!internetSetOptionW(INTERNET_OPTION_SETTINGS_CHANGED, null, 0)) return false;
    if (!internetSetOptionW(INTERNET_OPTION_PROXY_SETTINGS_CHANGED, null, 0)) return false;
    if (!internetSetOptionW(INTERNET_OPTION_REFRESH, null, 0)) return false;
    return true;
}

/// ASCII → UTF-16LE（host 为归一化 IP 字面量，ASCII 足够）。
fn asciiToUtf16(buf: []u16, s: []const u8) ?[:0]const u16 {
    if (s.len + 1 > buf.len) return null;
    for (s, 0..) |c, i| buf[i] = c;
    buf[s.len] = 0;
    return buf[0..s.len :0];
}

/// wininet 设置（失败 diag 填 GetLastError 数字）。
fn setWininetProxy(host: []const u8, port: u16, diag: *Diag) ProxyError!void {
    if (comptime !is_windows) return;
    var url_buf: [96]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "http://{s}:{d}", .{ host, port }) catch return error.EnableFailed;
    var utf16_buf: [96]u16 = undefined;
    const url_w = asciiToUtf16(&utf16_buf, url) orelse return error.EnableFailed;

    var options = [_]InternetPerConnOption{
        .{ .dw_option = INTERNET_PER_CONN_FLAGS, .value = PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT },
        .{ .dw_option = INTERNET_PER_CONN_PROXY_SERVER, .value = @intFromPtr(url_w.ptr) },
    };
    if (!setPerConnOptions(&options)) {
        diag.addFmt("InternetSetOptionW failed, GetLastError={d}", .{GetLastError()});
        return error.EnableFailed;
    }
}

/// wininet 恢复（PROXY_TYPE_DIRECT | AUTO_DETECT）。
fn restoreWininetProxy() void {
    if (comptime !is_windows) return;
    var options = [_]InternetPerConnOption{
        .{ .dw_option = INTERNET_PER_CONN_FLAGS, .value = PROXY_TYPE_DIRECT | PROXY_TYPE_AUTO_DETECT },
    };
    if (!setPerConnOptions(&options)) {
        std.log.warn("[sysproxy] restore failed (wininet)", .{});
    }
}

/// 执行 setx（写 HKCU\Environment）。成功返回 true。
fn runSetx(var_name: []const u8, value: []const u8) bool {
    if (comptime !is_windows) return false;
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "setx {s} \"{s}\" >nul", .{ var_name, value }) catch return false;
    var cmd_z: [512:0]u8 = undefined;
    @memcpy(cmd_z[0..cmd.len], cmd);
    cmd_z[cmd.len] = 0;
    return system(&cmd_z) == 0;
}

/// env 注入：http_proxy/https_proxy/no_proxy（Windows 大小写不敏感，设小写）。
fn injectEnv(host: []const u8, port: u16, diag: *Diag) void {
    var url_buf: [96]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "http://{s}:{d}", .{ host, port }) catch return;

    if (!runSetx("http_proxy", url)) diag.add("setx http_proxy failed");
    if (!runSetx("https_proxy", url)) diag.add("setx https_proxy failed");
    if (!runSetx("no_proxy", common.NO_PROXY_VALUE)) diag.add("setx no_proxy failed");
}

/// env 清理：setx 清空（best-effort）。
fn removeEnv() void {
    _ = runSetx("http_proxy", "");
    _ = runSetx("https_proxy", "");
    _ = runSetx("no_proxy", "");
}

// ============================================================================
// 对外入口（统一形状：setProxy / restoreProxy）
// ============================================================================

pub fn setProxy(
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    support_socks: bool,
    diag: *Diag,
) ProxyError!void {
    _ = allocator;
    _ = support_socks; // wininet 不支持系统级 SOCKS，忽略
    try setWininetProxy(host, port, diag);
    injectEnv(host, port, diag);
}

pub fn restoreProxy(allocator: std.mem.Allocator, support_socks: bool) void {
    _ = allocator;
    _ = support_socks;
    restoreWininetProxy();
    removeEnv();
}

// ============================================================================
// 测试
// ============================================================================

const testing = std.testing;

test "asciiToUtf16: ASCII 转 UTF-16LE" {
    var buf: [32]u16 = undefined;
    const w = asciiToUtf16(&buf, "http://127.0.0.1:7890").?;
    try testing.expectEqual(@as(usize, 21), w.len);
    try testing.expectEqual(@as(u16, 'h'), w[0]);
    try testing.expectEqual(@as(u16, 0), buf[21]); // 哨兵
}
