//! system_proxy_common — set_system_proxy 共享纯函数（#79）
//!
//! Linux/macOS 共用的环境变量注入逻辑（shell rc marker 区间读写）+
//! 地址归一化。Windows 走 setx 不用 shell rc，故不含于此。
//! 全部纯函数，跨平台可单测。
//!
//! marker 区间设计：begin/end marker 包围 export 块，restore 时精确删除
//! 区间（含 marker 行），防误删用户已有 proxy 设置。幂等：追加前先删旧区间。

const std = @import("std");

/// setProxy 失败错误（diag 携带系统原始错误信息，故错误集仅此一项）。
pub const ProxyError = error{EnableFailed};

/// 诊断累积器：持有 allocator，内部 ArrayList 操作无需每次传 allocator。
/// setProxy 失败时累积「系统原始错误信息」，应用层打印。
pub const Diag = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator) Diag {
        return .{ .allocator = allocator };
    }
    pub fn deinit(self: *Diag) void {
        self.items.deinit(self.allocator);
    }
    pub fn add(self: *Diag, text: []const u8) void {
        self.items.appendSlice(self.allocator, text) catch {};
    }
    pub fn addFmt(self: *Diag, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
        self.add(s);
    }
    pub fn slice(self: *const Diag) []const u8 {
        return self.items.items;
    }
};

/// 归一化系统代理主机地址：listen 为 unspecified（0.0.0.0 / ::）→ 127.0.0.1，
/// 其余原样返回。系统代理必须指向本机可拨的具体地址。
pub fn normalizeProxyHost(listen: []const u8) []const u8 {
    if (std.mem.eql(u8, listen, "0.0.0.0") or std.mem.eql(u8, listen, "::")) {
        return "127.0.0.1";
    }
    return listen;
}

// ============================================================================
// 环境变量注入（shell rc marker 区间）
// ============================================================================

pub const MARKER_BEGIN = "# >>> kisscore system proxy (set_system_proxy) >>>";
pub const MARKER_END = "# <<< kisscore system proxy (set_system_proxy) <<<";

/// 改名**前**的 marker（2026-09-30 zigbox → kisscore）。**只用于清理**，别拿它写新块。
///
/// 为什么必须认它：marker 是**写在用户 rc 文件里**的持久物，跨版本留在磁盘上。
/// 新代码若只认新 marker，旧版本写下的区间就永远删不掉 —— `removeFromShellRc`
/// 找不到它直接早退，「关掉代理」后 `http_proxy` 仍在；`appendToShellRc` 也不删它，
/// 于是 rc 里叠出两份 export（谁在后谁生效，用户看到的是关不掉的代理）。
///
/// ⚠️ 这是**一次性过渡**：被处理过一次的 rc 里不会再留旧区间，别再往这里加别名。
pub const LEGACY_MARKER_BEGIN = "# >>> zigbox system proxy (set_system_proxy) >>>";
pub const LEGACY_MARKER_END = "# <<< zigbox system proxy (set_system_proxy) <<<";

/// rc 内容里是否存在**任何一代** marker 区间（新旧都算）。
fn hasMarkerBlock(content: []const u8) bool {
    return std.mem.indexOf(u8, content, MARKER_BEGIN) != null or
        std.mem.indexOf(u8, content, LEGACY_MARKER_BEGIN) != null;
}

/// no_proxy 值：127.0.0.1 防回环（全平台必设，用户拍板 2026-08-23）。
pub const NO_PROXY_VALUE = "127.0.0.1,localhost,::1";

/// 构造 export 块（含 begin/end marker），写入 buf 返回有效切片，buf 不足返回 null。
/// http/https 恒设；no_proxy 恒设；大小写双设（不同工具读不同形式）。
/// support_socks 暂不参与 env 块（socks 经系统代理层；env 仅 http/https，避免
/// mixed-port 双代理坑——clash/mihomo 实测 http_proxy+all_proxy 同指 mixed 口会
/// 破坏非 HTTP 协议）。
pub fn buildExportBlock(buf: []u8, host: []const u8, port: u16) ?[]const u8 {
    var url_buf: [96]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "http://{s}:{d}", .{ host, port }) catch return null;
    return std.fmt.bufPrint(buf,
        \\{s}
        \\export http_proxy="{s}"
        \\export https_proxy="{s}"
        \\export HTTP_PROXY="{s}"
        \\export HTTPS_PROXY="{s}"
        \\export no_proxy="{s}"
        \\export NO_PROXY="{s}"
        \\{s}
        \\
    , .{
        MARKER_BEGIN,
        url,
        url,
        url,
        url,
        NO_PROXY_VALUE,
        NO_PROXY_VALUE,
        MARKER_END,
    }) catch null;
}

/// 删除内容中 `[begin, end]` 区间（含 marker 行），返回删除后的内容。
/// 找不到 begin/end 时原样返回（原地）。
fn stripBlock(content: []u8, begin: []const u8, end: []const u8) []u8 {
    const begin_idx = std.mem.indexOf(u8, content, begin) orelse return content;
    const end_idx = std.mem.indexOf(u8, content[begin_idx..], end) orelse return content;
    // end_idx 相对 begin_idx 起点；求 end 行的行尾（含换行）
    const end_abs = begin_idx + end_idx + end.len;
    var end_line = end_abs;
    if (end_line < content.len and content[end_line] == '\n') end_line += 1;
    // 删除 [begin_idx, end_line)：拼接前后两段
    std.mem.copyForwards(u8, content[begin_idx..], content[end_line..]);
    return content[0 .. content.len - (end_line - begin_idx)];
}

/// 删除内容中**任何一代** marker 区间：先删当前名，再删改名前的旧名。
/// 无 marker 时原样返回（原地）。
fn stripExistingBlock(content: []u8) []u8 {
    return stripBlock(stripBlock(content, MARKER_BEGIN, MARKER_END),
        LEGACY_MARKER_BEGIN, LEGACY_MARKER_END);
}

/// 读 shell rc 文件全部内容。文件不存在 → null；读失败 → null。
fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    const path_z = allocator.dupeZ(u8, path) catch return null;
    defer allocator.free(path_z);
    const fd = std.c.open(path_z.ptr, .{});
    if (fd < 0) return null;
    defer _ = std.c.close(fd);

    var content: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = std.c.read(fd, &buf, buf.len);
        if (n == 0) break;
        if (n < 0) {
            content.deinit(allocator);
            return null;
        }
        content.appendSlice(allocator, buf[0..@intCast(n)]) catch {
            content.deinit(allocator);
            return null;
        };
    }
    return content.toOwnedSlice(allocator) catch null;
}

/// 写 shell rc 文件（覆盖写）。成功返回 true。
fn writeFileAlloc(allocator: std.mem.Allocator, path: []const u8, content: []const u8) bool {
    const path_z = allocator.dupeZ(u8, path) catch return false;
    defer allocator.free(path_z);
    const fd = std.c.open(path_z.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return false;
    defer _ = std.c.close(fd);

    var written: usize = 0;
    while (written < content.len) {
        const n = std.c.write(fd, content[written..].ptr, content.len - written);
        if (n <= 0) return false;
        written += @intCast(n);
    }
    return true;
}

/// 追加 export 块到 shell rc：读 → 删旧 marker 区间 → 追加块 → 写回。
/// 幂等（重复调用不产生重复块）。失败返回 false（best-effort，调用方决定是否告警）。
pub fn appendToShellRc(allocator: std.mem.Allocator, path: []const u8, host: []const u8, port: u16) bool {
    var block_buf: [512]u8 = undefined;
    const block = buildExportBlock(&block_buf, host, port) orelse return false;

    const existing = readFileAlloc(allocator, path) orelse &.{};
    defer if (existing.len > 0) allocator.free(existing);

    // 构造新内容：删旧块 + 确保末尾换行 + 追加块
    const stripped = stripExistingBlock(@constCast(existing));
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    out.appendSlice(allocator, stripped) catch return false;
    if (stripped.len > 0 and stripped[stripped.len - 1] != '\n')
        out.append(allocator, '\n') catch return false;
    out.appendSlice(allocator, block) catch return false;

    return writeFileAlloc(allocator, path, out.items);
}

/// 从 shell rc 删除 marker 区间（best-effort）。无 marker 时不动文件。
pub fn removeFromShellRc(allocator: std.mem.Allocator, path: []const u8) void {
    const existing = readFileAlloc(allocator, path) orelse return;
    defer allocator.free(existing);

    if (!hasMarkerBlock(existing)) return;
    const stripped = stripExistingBlock(@constCast(existing));
    _ = writeFileAlloc(allocator, path, stripped);
}

// ============================================================================
// 测试
// ============================================================================

const testing = std.testing;

test "normalizeProxyHost: unspecified → 127.0.0.1" {
    try testing.expectEqualStrings("127.0.0.1", normalizeProxyHost("0.0.0.0"));
    try testing.expectEqualStrings("127.0.0.1", normalizeProxyHost("::"));
    try testing.expectEqualStrings("127.0.0.1", normalizeProxyHost("127.0.0.1"));
    try testing.expectEqualStrings("192.168.1.5", normalizeProxyHost("192.168.1.5"));
    try testing.expectEqualStrings("::1", normalizeProxyHost("::1"));
}

test "buildExportBlock: 含 marker + http/https + no_proxy 大小写双设" {
    var buf: [512]u8 = undefined;
    const block = buildExportBlock(&buf, "127.0.0.1", 7890).?;
    try testing.expect(std.mem.indexOf(u8, block, MARKER_BEGIN) != null);
    try testing.expect(std.mem.indexOf(u8, block, MARKER_END) != null);
    try testing.expect(std.mem.indexOf(u8, block, "http_proxy=\"http://127.0.0.1:7890\"") != null);
    try testing.expect(std.mem.indexOf(u8, block, "https_proxy=\"http://127.0.0.1:7890\"") != null);
    try testing.expect(std.mem.indexOf(u8, block, "HTTP_PROXY=\"http://127.0.0.1:7890\"") != null);
    try testing.expect(std.mem.indexOf(u8, block, "HTTPS_PROXY=\"http://127.0.0.1:7890\"") != null);
    try testing.expect(std.mem.indexOf(u8, block, "no_proxy=\"127.0.0.1,localhost,::1\"") != null);
    try testing.expect(std.mem.indexOf(u8, block, "NO_PROXY=\"127.0.0.1,localhost,::1\"") != null);
}

test "stripExistingBlock: 删旧块保留前后内容" {
    const before = "export PATH=/usr/bin\n";
    const after = "export FOO=bar\n";
    var block_buf: [512]u8 = undefined;
    const block = buildExportBlock(&block_buf, "127.0.0.1", 7890).?;

    const input = std.mem.concat(testing.allocator, u8, &.{ before, block, after }) catch unreachable;
    defer testing.allocator.free(input);

    const expected = std.mem.concat(testing.allocator, u8, &.{ before, after }) catch unreachable;
    defer testing.allocator.free(expected);

    const stripped = stripExistingBlock(@constCast(input));
    try testing.expectEqualStrings(expected, stripped);
}

test "stripExistingBlock: 幂等（删后无 marker 再删原样）" {
    const before = "export PATH=/usr/bin\n";
    var block_buf: [512]u8 = undefined;
    const block = buildExportBlock(&block_buf, "127.0.0.1", 7890).?;

    const input = std.mem.concat(testing.allocator, u8, &.{ before, block }) catch unreachable;
    defer testing.allocator.free(input);

    const once = stripExistingBlock(@constCast(input));
    const twice = stripExistingBlock(@constCast(once));
    try testing.expectEqualStrings(before, once);
    try testing.expectEqualStrings(once, twice);
}

/// 造一个「改名前的版本写下的」区间：旧 marker + 同形的 export 行。
fn legacyExportBlock(buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf,
        \\{s}
        \\export http_proxy="http://127.0.0.1:7890"
        \\{s}
        \\
    , .{ LEGACY_MARKER_BEGIN, LEGACY_MARKER_END }) catch unreachable;
}

test "marker 改名迁移: 只有旧 marker 的 rc 也必须被认出来并删净" {
    var lbuf: [512]u8 = undefined;
    const legacy = legacyExportBlock(&lbuf);

    // 改名前写入的 rc：旧区间在，新区间不在
    const input = std.mem.concat(testing.allocator, u8, &.{ "export PATH=/usr/bin\n", legacy }) catch unreachable;
    defer testing.allocator.free(input);
    try testing.expect(hasMarkerBlock(input)); // 判据：旧 marker 也算「有」
    try testing.expectEqualStrings("export PATH=/usr/bin\n", stripExistingBlock(@constCast(input)));
}

test "marker 改名迁移: 新旧两代并存也一并删净（不叠两份 export）" {
    var lbuf: [512]u8 = undefined;
    var nbuf: [512]u8 = undefined;
    const legacy = legacyExportBlock(&lbuf);
    const current = buildExportBlock(&nbuf, "127.0.0.1", 7890).?;

    const input = std.mem.concat(testing.allocator, u8, &.{ legacy, current }) catch unreachable;
    defer testing.allocator.free(input);

    const stripped = stripExistingBlock(@constCast(input));
    try testing.expectEqualStrings("", stripped);
    try testing.expect(!hasMarkerBlock(stripped));
}

test "marker 改名迁移: 未涉内容不误判、不误删（含用户自己的 proxy 行）" {
    const user = "export PATH=/usr/bin\nexport http_proxy=http://10.0.0.1:1080\n";
    try testing.expect(!hasMarkerBlock(user));
    const copy = testing.allocator.dupe(u8, user) catch unreachable;
    defer testing.allocator.free(copy);
    try testing.expectEqualStrings(user, stripExistingBlock(copy));
}

test "marker 改名迁移（端到端）: removeFromShellRc 真的把旧区间从磁盘上清掉" {
    const path = "/tmp/zignetmon_legacy_marker_rc";
    defer _ = std.c.unlink(path);

    var lbuf: [512]u8 = undefined;
    const legacy = legacyExportBlock(&lbuf);
    const content = std.mem.concat(testing.allocator, u8, &.{ "export PATH=/usr/bin\n", legacy }) catch unreachable;
    defer testing.allocator.free(content);
    try testing.expect(writeFileAlloc(testing.allocator, path, content));

    removeFromShellRc(testing.allocator, path);

    const after = readFileAlloc(testing.allocator, path).?;
    defer testing.allocator.free(after);
    // 真症状：关掉代理后 http_proxy 不得残留
    try testing.expect(std.mem.indexOf(u8, after, "http_proxy") == null);
    try testing.expect(!hasMarkerBlock(after));
    try testing.expectEqualStrings("export PATH=/usr/bin\n", after);
}
