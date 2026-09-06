//! system_proxy_linux — Linux 系统代理平台实现（#79）
//!
//! 系统代理：尽力而为 gsettings (GNOME) / kwriteconfig5|6 (KDE)，均无则跳过，
//! 对标 vendor/sing-box/common/settings/proxy_linux.go。
//! env 注入：目标用户 ~/.bashrc + ~/.zshrc（common.appendToShellRc/removeFromShellRc）。
//!
//! 降权找目标用户（#79 增强）：
//!   - 非 root：当前用户（getuid + HOME/USER）。
//!   - root + SUDO_USER：经 getpwnam 查 home。
//!   - root 无 SUDO_USER：解析 /etc/passwd 找真实登录用户（uid≥1000、有 home、
//!     shell 非 nologin/false）兜底。
//!
//! 错误语义：系统代理（gsettings/kwriteconfig）失败 → diag 累积 stderr → return
//! error.EnableFailed；env 注入失败仅 append 诊断（软约束）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const common = @import("system_proxy_common.zig");

const ProxyError = common.ProxyError;
const Diag = common.Diag;

// ============================================================================
// C 运行时（shell 执行 / passwd 查询）
// ============================================================================

extern "c" fn system(command: [*:0]const u8) c_int;
extern "c" fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
extern "c" fn pclose(stream: *anyopaque) c_int;
extern "c" fn fgetc(stream: *anyopaque) c_int;

/// 执行 shell 命令，捕获 stdout+stderr。成功（退出码 0）返回 true；
/// 失败把输出 append 到 diag 返回 false。
fn runShellCapturing(cmd: []const u8, diag: *Diag) bool {
    var cmd_z: [1024:0]u8 = undefined;
    if (cmd.len + 6 >= cmd_z.len) return false;
    @memcpy(cmd_z[0..cmd.len], cmd);
    @memcpy(cmd_z[cmd.len .. cmd.len + 5], " 2>&1");
    cmd_z[cmd.len + 5] = 0;

    const pipe = popen(&cmd_z, "r") orelse {
        diag.add("popen failed");
        return false;
    };
    var out: [512]u8 = undefined;
    var n: usize = 0;
    while (n < out.len) : (n += 1) {
        const c = fgetc(pipe);
        if (c == -1) break;
        out[n] = @intCast(c);
    }
    const status = pclose(pipe);
    if (status == 0) return true;
    diag.add(out[0..n]);
    return false;
}

/// 命令是否存在于 PATH（command -v）。
fn linuxHasCmd(name: []const u8, diag: *Diag) bool {
    var probe_buf: [128]u8 = undefined;
    const probe = std.fmt.bufPrint(&probe_buf, "command -v {s} >/dev/null 2>&1", .{name}) catch return false;
    return runShellCapturing(probe, diag);
}

// ============================================================================
// 降权找目标用户（#79 增强）
// ============================================================================

const TargetUser = struct {
    /// 用户名（allocator 分配，调用者释放）
    username: []const u8,
    /// home 目录（allocator 分配，调用者释放）
    home: []const u8,
};

fn dupe(allocator: std.mem.Allocator, s: []const u8) ?[]const u8 {
    return allocator.dupe(u8, s) catch null;
}

/// 读环境变量（返回 allocator 副本）。
fn getEnv(allocator: std.mem.Allocator, name: [*:0]const u8) ?[]const u8 {
    const raw = std.c.getenv(name) orelse return null;
    return dupe(allocator, std.mem.sliceTo(raw, 0));
}

/// 解析 /etc/passwd 找真实登录用户：uid≥1000、home 非空、shell 非 nologin/false。
/// 返回 { username, home }（allocator 分配）。找不到返回 null。
fn findRealUserFromPasswd(allocator: std.mem.Allocator) ?TargetUser {
    const path_z = allocator.dupeZ(u8, "/etc/passwd") catch return null;
    defer allocator.free(path_z);
    const fd = std.c.open(path_z.ptr, .{});
    if (fd < 0) return null;
    defer _ = std.c.close(fd);

    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.c.read(fd, &buf, buf.len);
        if (n <= 0) break;
        content.appendSlice(allocator, buf[0..@intCast(n)]) catch return null;
    }

    var lines = std.mem.splitScalar(u8, content.items, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        // name:passwd:uid:gid:gecos:home:shell
        var cols = std.mem.splitScalar(u8, line, ':');
        const name = cols.next() orelse continue;
        _ = cols.next() orelse continue; // passwd
        const uid_str = cols.next() orelse continue;
        _ = cols.next() orelse continue; // gid
        _ = cols.next() orelse continue; // gecos
        const home = cols.next() orelse continue;
        const shell = cols.next() orelse continue;

        const uid = std.fmt.parseInt(u32, uid_str, 10) catch continue;
        if (uid < 1000) continue;
        if (home.len == 0) continue;
        if (std.mem.endsWith(u8, shell, "nologin") or std.mem.endsWith(u8, shell, "false")) continue;

        const username = dupe(allocator, name) orelse return null;
        const home_owned = dupe(allocator, home) orelse {
            allocator.free(username);
            return null;
        };
        return .{ .username = username, .home = home_owned };
    }
    return null;
}

/// 解析目标用户（系统代理降权 + env 注入共用）。
fn resolveTargetUser(allocator: std.mem.Allocator) ?TargetUser {
    const uid = std.os.linux.getuid();
    if (uid != 0) {
        // 非 root：当前用户
        const username = getEnv(allocator, "USER") orelse dupe(allocator, "user") orelse return null;
        const home = getEnv(allocator, "HOME") orelse return null;
        return .{ .username = username, .home = home };
    }
    // root：SUDO_USER 优先
    if (getEnv(allocator, "SUDO_USER")) |sudo_user| {
        defer allocator.free(sudo_user);
        var name_z_buf: [64]u8 = undefined;
        const name_z = std.fmt.bufPrintZ(&name_z_buf, "{s}", .{sudo_user}) catch return null;
        if (std.c.getpwnam(name_z.ptr)) |pw| {
            const dir = std.mem.sliceTo(pw.dir, 0) orelse return null; // 0.16 passwd.dir 是 ?[*:0]const u8
            const home = dupe(allocator, dir) orelse return null;
            return .{ .username = sudo_user, .home = home };
        }
    }
    // root 无 SUDO_USER：/etc/passwd 兜底
    return findRealUserFromPasswd(allocator);
}

/// 释放 TargetUser（home 与 username 均 allocator 分配）。
fn freeTargetUser(allocator: std.mem.Allocator, u: TargetUser) void {
    allocator.free(u.home);
    allocator.free(u.username);
}

// ============================================================================
// 系统代理（gsettings / kwriteconfig）
// ============================================================================

/// 以目标用户身份执行命令（root 时经 su 降权，非 root 直接执行）。
fn runLinuxAsUser(target: TargetUser, name: []const u8, args: []const u8, diag: *Diag) bool {
    const is_root = std.os.linux.getuid() == 0;
    if (!is_root) {
        var cmd_buf: [1024]u8 = undefined;
        const cmd = std.fmt.bufPrint(&cmd_buf, "{s} {s}", .{ name, args }) catch return false;
        return runShellCapturing(cmd, diag);
    }
    var cmd_buf: [1024]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "su - '{s}' -c '{s} {s}'", .{ target.username, name, args }) catch return false;
    return runShellCapturing(cmd, diag);
}

/// gsettings 代理命令参数序列（纯函数，本机可测）— 返回 `set ... && ...` 串，
/// 由 runLinuxAsUser 以 "gsettings <args>" 执行。http/https host+port 恒设；
/// socks 项仅 support_socks（#75：http-only 入站不把系统 socks 指向不支持 socks
/// 协议的 http 入站端口）；mode manual 收尾使代理生效。
pub fn buildLinuxGsettingsArgs(buf: []u8, host: []const u8, port: u16, support_socks: bool) ?[]const u8 {
    const name = "gsettings";
    var pos: usize = 0;
    const types = [_][]const u8{ "http", "https" };
    for (types) |t| {
        const piece = std.fmt.bufPrint(buf[pos..], "set org.gnome.system.proxy.{s} host '{s}' && {s} set org.gnome.system.proxy.{s} port {d} && ", .{ t, host, name, t, port }) catch return null;
        pos += piece.len;
    }
    if (support_socks) {
        const piece = std.fmt.bufPrint(buf[pos..], "set org.gnome.system.proxy.socks host '{s}' && {s} set org.gnome.system.proxy.socks port {d} && ", .{ host, name, port }) catch return null;
        pos += piece.len;
    }
    const piece = std.fmt.bufPrint(buf[pos..], "{s} set org.gnome.system.proxy mode 'manual'", .{name}) catch return null;
    pos += piece.len;
    return buf[0..pos];
}

fn setDesktopProxyScheme(target: TargetUser, name: []const u8, host: []const u8, port: u16, support_socks: bool, diag: *Diag) bool {
    if (std.mem.eql(u8, name, "gsettings")) {
        var args_buf: [512]u8 = undefined;
        const args = buildLinuxGsettingsArgs(&args_buf, host, port, support_socks) orelse return false;
        return runLinuxAsUser(target, name, args, diag);
    } else {
        // KDE：kwriteconfig kioslaverc Proxy Type 1 + http/https host/port
        var args_buf: [512]u8 = undefined;
        const args = std.fmt.bufPrint(&args_buf, "--file kioslaverc --group 'Proxy Settings' --key ProxyType 1 --key httpProxy 'http://{s}:{d}' --key httpsProxy 'http://{s}:{d}'", .{ host, port, host, port }) catch return false;
        if (!runLinuxAsUser(target, name, args, diag)) return false;
        return runLinuxAsUser(target, "dbus-send", "--type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration string:''", diag);
    }
}

/// 桌面代理工具选择：gsettings > kwriteconfig6 > kwriteconfig5 > null。
pub fn pickDesktopAgent(has_gsettings: bool, has_kwrite6: bool, has_kwrite5: bool) ?[]const u8 {
    if (has_gsettings) return "gsettings";
    if (has_kwrite6) return "kwriteconfig6";
    if (has_kwrite5) return "kwriteconfig5";
    return null;
}

// ============================================================================
// env 注入（目标用户 shell rc）
// ============================================================================

fn injectEnv(allocator: std.mem.Allocator, target: TargetUser, host: []const u8, port: u16, diag: *Diag) void {
    for ([_][]const u8{ ".bashrc", ".zshrc" }) |rc| {
        const path = std.fs.path.join(allocator, &.{ target.home, rc }) catch continue;
        defer allocator.free(path);
        if (!common.appendToShellRc(allocator, path, host, port)) {
            diag.addFmt("append to {s} failed", .{path});
        }
    }
}

fn removeEnv(allocator: std.mem.Allocator, target: TargetUser) void {
    for ([_][]const u8{ ".bashrc", ".zshrc" }) |rc| {
        const path = std.fs.path.join(allocator, &.{ target.home, rc }) catch continue;
        defer allocator.free(path);
        common.removeFromShellRc(allocator, path);
    }
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
    // 桌面代理工具探测（无桌面 → 跳过系统代理，仅 env 注入）
    const agent = pickDesktopAgent(linuxHasCmd("gsettings", diag), linuxHasCmd("kwriteconfig6", diag), linuxHasCmd("kwriteconfig5", diag));

    // 解析目标用户（env 注入始终需要；系统代理仅在 root 时降权）
    const target = resolveTargetUser(allocator) orelse {
        diag.add("cannot resolve target user");
        return error.EnableFailed;
    };
    defer freeTargetUser(allocator, target);

    if (agent) |name| {
        if (!setDesktopProxyScheme(target, name, host, port, support_socks, diag)) {
            diag.addFmt("system proxy enable failed via {s}", .{name});
            return error.EnableFailed;
        }
    } else {
        std.log.warn("[sysproxy] unsupported desktop environment (no gsettings/kwriteconfig), system proxy skipped", .{});
    }

    injectEnv(allocator, target, host, port, diag);
}

pub fn restoreProxy(allocator: std.mem.Allocator, support_socks: bool) void {
    _ = support_socks;
    const target = resolveTargetUser(allocator) orelse return;
    defer freeTargetUser(allocator, target);

    var diag = Diag.init(allocator);
    defer diag.deinit();
    const agent = pickDesktopAgent(linuxHasCmd("gsettings", &diag), linuxHasCmd("kwriteconfig6", &diag), linuxHasCmd("kwriteconfig5", &diag));
    if (agent) |name| {
        if (std.mem.eql(u8, name, "gsettings")) {
            _ = runLinuxAsUser(target, "gsettings", "set org.gnome.system.proxy mode 'none'", &diag);
        } else {
            _ = runLinuxAsUser(target, name, "--file kioslaverc --group 'Proxy Settings' --key ProxyType 0", &diag);
            _ = runLinuxAsUser(target, "dbus-send", "--type=signal /KIO/Scheduler org.kde.KIO.Scheduler.reparseSlaveConfiguration string:''", &diag);
        }
    }
    removeEnv(allocator, target);
}

// ============================================================================
// 测试
// ============================================================================

const testing = std.testing;

test "pickDesktopAgent 真值表" {
    try testing.expectEqualStrings("gsettings", pickDesktopAgent(true, false, false).?);
    try testing.expectEqualStrings("gsettings", pickDesktopAgent(true, true, true).?);
    try testing.expectEqualStrings("kwriteconfig6", pickDesktopAgent(false, true, false).?);
    try testing.expectEqualStrings("kwriteconfig6", pickDesktopAgent(false, true, true).?);
    try testing.expectEqualStrings("kwriteconfig5", pickDesktopAgent(false, false, true).?);
    try testing.expect(pickDesktopAgent(false, false, false) == null);
}

test "buildLinuxGsettingsArgs: support_socks 真值表" {
    var buf: [512]u8 = undefined;
    const with_socks = buildLinuxGsettingsArgs(&buf, "127.0.0.1", 12080, true).?;
    try testing.expect(std.mem.indexOf(u8, with_socks, "system.proxy.http host '127.0.0.1'") != null);
    try testing.expect(std.mem.indexOf(u8, with_socks, "system.proxy.https host '127.0.0.1'") != null);
    try testing.expect(std.mem.indexOf(u8, with_socks, "system.proxy.socks host '127.0.0.1'") != null);
    try testing.expect(std.mem.indexOf(u8, with_socks, "system.proxy mode 'manual'") != null);
    try testing.expect(std.mem.indexOf(u8, with_socks, "port 12080") != null);

    const no_socks = buildLinuxGsettingsArgs(&buf, "127.0.0.1", 12080, false).?;
    try testing.expect(std.mem.indexOf(u8, no_socks, "system.proxy.socks") == null);
    try testing.expect(std.mem.indexOf(u8, no_socks, "system.proxy.http host '127.0.0.1'") != null);
    try testing.expect(std.mem.indexOf(u8, no_socks, "system.proxy.https host '127.0.0.1'") != null);
    try testing.expect(std.mem.indexOf(u8, no_socks, "system.proxy mode 'manual'") != null);
}
