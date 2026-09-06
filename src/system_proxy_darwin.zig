//! system_proxy_darwin — macOS 系统代理平台实现（#79）
//!
//! 系统代理：networksetup 命令行（-setwebproxy/-setsecurewebproxy[/-setsocksfirewallproxy]），
//! 对标 vendor/sing-box/common/settings/proxy_darwin.go。
//! env 注入：~/.bashrc + ~/.zshrc（common.appendToShellRc/removeFromShellRc，双写）。
//! 默认接口名：zf.network 快照 → zf.egress 索引 → if_indextoname（重建路径）。
//!
//! 错误语义：setProxy 系统代理失败 → diag 累积命令 stderr → return error.EnableFailed；
//! env 注入失败仅 append 诊断到 diag（软约束，不 fail）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const common = @import("system_proxy_common.zig");

const ProxyError = common.ProxyError;
const Diag = common.Diag;

// ============================================================================
// C 运行时（shell 命令执行 / 接口名反查）
// ============================================================================

extern "c" fn system(command: [*:0]const u8) c_int;
extern "c" fn popen(command: [*:0]const u8, mode: [*:0]const u8) ?*anyopaque;
extern "c" fn pclose(stream: *anyopaque) c_int;
extern "c" fn fgetc(stream: *anyopaque) c_int;
extern "c" fn if_indextoname(ifindex: c_uint, ifname: [*]u8) ?[*:0]u8;

/// 转义 shell 单引号包裹的字符串：' → '"'"'（POSIX shell 单引号转义惯用法）。
/// service 为 networksetup 服务显示名，理论上用户可自定义含单引号；转义后
/// shell 展开仍还原为原字面量，杜绝命令注入。buf 不足返回 buf[0..0]。
pub fn escapeSingleQuotes(buf: []u8, s: []const u8) []const u8 {
    const escape = "'\"'\"'"; // ' → '"'"'
    var out: usize = 0;
    for (s) |c| {
        if (c == '\'') {
            if (out + escape.len > buf.len) return buf[0..0];
            @memcpy(buf[out .. out + escape.len], escape);
            out += escape.len;
        } else {
            if (out + 1 > buf.len) return buf[0..0];
            buf[out] = c;
            out += 1;
        }
    }
    return buf[0..out];
}

/// 构造 networksetup 设置命令（纯函数，供单元测试断言参数序列）。
/// kind: web / secure_web / socks → -setwebproxy / -setsecurewebproxy / -setsocksfirewallproxy
pub fn buildDarwinSetCmd(buf: []u8, kind: enum { web, secure_web, socks }, service: []const u8, host: []const u8, port: u16) []const u8 {
    const flag = switch (kind) {
        .web => "-setwebproxy",
        .secure_web => "-setsecurewebproxy",
        .socks => "-setsocksfirewallproxy",
    };
    var svc_buf: [128]u8 = undefined;
    const svc = escapeSingleQuotes(&svc_buf, service);
    return std.fmt.bufPrint(buf, "networksetup {s} '{s}' {s} {d}", .{ flag, svc, host, port }) catch buf[0..0];
}

/// 构造 networksetup 关闭命令。kind 同上 → *-state off。
pub fn buildDarwinStateOffCmd(buf: []u8, kind: enum { web, secure_web, socks }, service: []const u8) []const u8 {
    const flag = switch (kind) {
        .web => "-setwebproxystate",
        .secure_web => "-setsecurewebproxystate",
        .socks => "-setsocksfirewallproxystate",
    };
    var svc_buf: [128]u8 = undefined;
    const svc = escapeSingleQuotes(&svc_buf, service);
    return std.fmt.bufPrint(buf, "networksetup {s} '{s}' off", .{ flag, svc }) catch buf[0..0];
}

/// 执行 shell 命令，捕获 stdout+stderr。成功（退出码 0）返回 true；
/// 失败把输出 append 到 diag 返回 false。
fn runShellCapturing(cmd: []const u8, diag: *Diag) bool {
    var cmd_z: [768:0]u8 = undefined;
    if (cmd.len + 6 >= cmd_z.len) return false;
    @memcpy(cmd_z[0..cmd.len], cmd);
    // 追加 " 2>&1" 捕获 stderr
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

/// 从 networksetup -listallhardwareports 输出按 "Device: <name>" 反查
/// "Hardware Port: <显示名>"（输出顺序为 Hardware Port 在前、Device 在后，
/// 记录最近一次 Hardware Port 行，遇到匹配 Device 行即返回 — 与上游
/// proxy_darwin.go:107-121 的 split 语义等价）。
pub fn parseHardwarePort(output: []const u8, device: []const u8, out: []u8) ?[]const u8 {
    var last_port: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (std.mem.indexOf(u8, line, "Hardware Port: ")) |idx| {
            last_port = std.mem.trim(u8, line[idx + "Hardware Port: ".len ..], " \t\r");
        } else if (std.mem.indexOf(u8, line, "Device: ")) |idx| {
            const dev = std.mem.trim(u8, line[idx + "Device: ".len ..], " \t\r");
            if (std.mem.eql(u8, dev, device)) {
                const port = last_port orelse return null;
                if (port.len == 0 or port.len > out.len) return null;
                @memcpy(out[0..port.len], port);
                return out[0..port.len];
            }
        }
    }
    return null;
}

/// 接口显示名反查（执行 networksetup -listallhardwareports）。
fn getInterfaceDisplayName(device: []const u8, out: []u8) ?[]const u8 {
    const pipe = popen("networksetup -listallhardwareports 2>/dev/null", "r") orelse return null;
    defer _ = pclose(pipe);

    var output_buf: [4096]u8 = undefined;
    var idx: usize = 0;
    while (idx < output_buf.len) : (idx += 1) {
        const c = fgetc(pipe);
        if (c == -1) break;
        output_buf[idx] = @intCast(c);
    }
    return parseHardwarePort(output_buf[0..idx], device, out);
}

/// 当前默认接口名：优先 zf.network 快照（网络监控已启动时 — 重建路径），
/// 首个 Session start 早于 core.run 的 zf.network.init/start，快照无数据，
/// 降级到 zf.egress.getDefaultInterfaceIndex + if_indextoname（route 表探测，
/// 与 egress 探测同源 — 两条路径结果一致）。
fn defaultInterfaceName(out: []u8) ?[]const u8 {
    const info = zf.network.snapshot();
    if (info.default_interface) |iface| {
        if (iface.name_len > 0 and iface.name_len <= out.len) {
            @memcpy(out[0..iface.name_len], iface.name[0..iface.name_len]);
            return out[0..iface.name_len];
        }
    }
    const idx = zf.egress.getDefaultInterfaceIndex() orelse return null;
    var name_buf: [16]u8 = undefined;
    const ptr = if_indextoname(@intCast(idx), &name_buf) orelse return null;
    const name = std.mem.sliceTo(ptr, 0);
    if (name.len == 0 or name.len > out.len) return null;
    @memcpy(out[0..name.len], name);
    return out[0..name.len];
}

/// 取默认网络服务的显示名（设备名 → networksetup 服务显示名）。
fn getPrimaryServiceName(buf: []u8) ?[]const u8 {
    var dev_buf: [64]u8 = undefined;
    const device = defaultInterfaceName(&dev_buf) orelse return null;
    return getInterfaceDisplayName(device, buf);
}

/// 设置系统代理（networksetup）。失败 return error.EnableFailed（diag 已填 stderr）。
fn setDarwinSystemProxy(host: []const u8, port: u16, support_socks: bool, diag: *Diag) ProxyError!void {
    var svc_buf: [128]u8 = undefined;
    const service = getPrimaryServiceName(&svc_buf) orelse {
        diag.add("no default interface for networksetup");
        return error.EnableFailed;
    };

    var cmd_buf: [512]u8 = undefined;
    // 顺序对齐上游 update0：socks（可选）→ web → secure web
    if (support_socks) {
        if (!runShellCapturing(buildDarwinSetCmd(&cmd_buf, .socks, service, host, port), diag)) return error.EnableFailed;
    }
    if (!runShellCapturing(buildDarwinSetCmd(&cmd_buf, .web, service, host, port), diag)) return error.EnableFailed;
    if (!runShellCapturing(buildDarwinSetCmd(&cmd_buf, .secure_web, service, host, port), diag)) return error.EnableFailed;
}

/// 恢复系统代理（networksetup state off，best-effort 仅 warn）。
fn restoreDarwinSystemProxy(support_socks: bool) void {
    var svc_buf: [128]u8 = undefined;
    const service = getPrimaryServiceName(&svc_buf) orelse return;

    var diag = Diag.init(std.heap.page_allocator);
    defer diag.deinit();

    var cmd_buf: [512]u8 = undefined;
    if (support_socks) {
        if (!runShellCapturing(buildDarwinStateOffCmd(&cmd_buf, .socks, service), &diag))
            std.log.warn("[sysproxy] restore socks failed: service={s}", .{service});
    }
    if (!runShellCapturing(buildDarwinStateOffCmd(&cmd_buf, .web, service), &diag))
        std.log.warn("[sysproxy] restore web failed: service={s}", .{service});
    if (!runShellCapturing(buildDarwinStateOffCmd(&cmd_buf, .secure_web, service), &diag))
        std.log.warn("[sysproxy] restore secure web failed: service={s}", .{service});
}

/// 获取当前用户 HOME 目录（macOS 进程即用户，直接读 HOME）。
fn getHomeDir(allocator: std.mem.Allocator) ?[]const u8 {
    const raw = std.c.getenv("HOME") orelse return null;
    return allocator.dupe(u8, std.mem.sliceTo(raw, 0)) catch null;
}

/// env 注入（双写 ~/.bashrc + ~/.zshrc，软约束：失败仅 append diag）。
fn injectEnv(allocator: std.mem.Allocator, host: []const u8, port: u16, diag: *Diag) void {
    const home = getHomeDir(allocator) orelse {
        diag.add("no HOME for shell rc injection");
        return;
    };
    defer allocator.free(home);

    for ([_][]const u8{ ".bashrc", ".zshrc" }) |rc| {
        const path = std.fs.path.join(allocator, &.{ home, rc }) catch continue;
        defer allocator.free(path);
        if (!common.appendToShellRc(allocator, path, host, port)) {
            diag.addFmt("append to {s} failed", .{path});
        }
    }
}

/// env 清理（best-effort，删两个 rc 的 marker 区间）。
fn removeEnv(allocator: std.mem.Allocator) void {
    const home = getHomeDir(allocator) orelse return;
    defer allocator.free(home);

    for ([_][]const u8{ ".bashrc", ".zshrc" }) |rc| {
        const path = std.fs.path.join(allocator, &.{ home, rc }) catch continue;
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
    try setDarwinSystemProxy(host, port, support_socks, diag);
    injectEnv(allocator, host, port, diag);
}

pub fn restoreProxy(allocator: std.mem.Allocator, support_socks: bool) void {
    restoreDarwinSystemProxy(support_socks);
    removeEnv(allocator);
}

// ============================================================================
// 测试
// ============================================================================

const testing = std.testing;

test "darwin 命令构造：参数序列断言（不执行）" {
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(
        "networksetup -setsocksfirewallproxy 'Wi-Fi' 127.0.0.1 7890",
        buildDarwinSetCmd(&buf, .socks, "Wi-Fi", "127.0.0.1", 7890),
    );
    try testing.expectEqualStrings(
        "networksetup -setwebproxy 'Wi-Fi' 127.0.0.1 7890",
        buildDarwinSetCmd(&buf, .web, "Wi-Fi", "127.0.0.1", 7890),
    );
    try testing.expectEqualStrings(
        "networksetup -setsecurewebproxy 'Ethernet' 127.0.0.1 7890",
        buildDarwinSetCmd(&buf, .secure_web, "Ethernet", "127.0.0.1", 7890),
    );
    try testing.expectEqualStrings(
        "networksetup -setwebproxystate 'Wi-Fi' off",
        buildDarwinStateOffCmd(&buf, .web, "Wi-Fi"),
    );
}

test "parseHardwarePort: Device 反查 Hardware Port" {
    const output =
        "Hardware Port: Wi-Fi\n" ++
        "Device: en0\n" ++
        "Ethernet Address: aa:bb:cc:dd:ee:ff\n" ++
        "\n" ++
        "Hardware Port: Ethernet Adapter\n" ++
        "Device: en5\n" ++
        "Ethernet Address: 11:22:33:44:55:66\n";
    var out: [64]u8 = undefined;
    try testing.expectEqualStrings("Wi-Fi", parseHardwarePort(output, "en0", &out).?);
    try testing.expectEqualStrings("Ethernet Adapter", parseHardwarePort(output, "en5", &out).?);
    try testing.expect(parseHardwarePort(output, "en9", &out) == null);
}

test "escapeSingleQuotes: 单引号转义" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("Wi-Fi", escapeSingleQuotes(&buf, "Wi-Fi"));
    try testing.expectEqualStrings("", escapeSingleQuotes(&buf, ""));
    try testing.expectEqualStrings("'\"'\"'", escapeSingleQuotes(&buf, "'"));
    try testing.expectEqualStrings("Foo'\"'\"'Bar", escapeSingleQuotes(&buf, "Foo'Bar"));
}

test "darwin 命令构造：service 含单引号转义" {
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(
        "networksetup -setwebproxy 'Foo'\"'\"'Bar' 127.0.0.1 7890",
        buildDarwinSetCmd(&buf, .web, "Foo'Bar", "127.0.0.1", 7890),
    );
}
