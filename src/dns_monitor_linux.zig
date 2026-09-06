//! 系统 DNS 变化监测 — Linux 后端（design.md §3/§5）。
//!
//! 目标事件源：Linux 桌面/服务器把系统 DNS 写进 `/etc/resolv.conf`（systemd-resolved /
//! NetworkManager / dhclient / 手动修改都会重写它）。本文件用 **inotify** 监听该文件，
//! 变化 → 重读当前 DNS（network_params.queryDnsServers 解析同一文件）→ diff → emit。
//!
//! ## 监听蒙版 + mtime diff 兜底（双保险，本文件实现要点）
//!   - inotify 直接 watch `/etc/resolv.conf`（IN_CLOSE_WRITE|IN_MOVED_TO|IN_DELETE|
//!     IN_ATTRIB）。多数写入（写后关闭、原地覆盖）能命中。
//!   - ⚠️ rename 替换（原子换文件、systemd-resolved 常见）会使已 watch 的 inode 失效：
//!     旧 inode 收 IN_DELETE_SELF/IN_IGNORED、新 inode 不在 watch 内。故事件后无条件
//!     重挂 watch + 后台线程每 ~1s 对文件做一次 **stat mtime 兜底**（相对上次基线变了才
//!     触发重读），覆盖 inotify 失效窗口下的变化（替换 / 缺失文件新建）。
//!   - 所有触发都走「重读 → diff（ipEqual）→ 仅真变化 emit」，重复触发自然去重。
//!
//! ## 平台说明
//! 本文件仅 Linux（非 android）目标编译/运行（comptime 分派，见 dns_monitor.zig）；
//! Android 归 stub（移动端 DNS 注入承载）。后台线程阻塞在 poll(100ms 超时)（非忙等），
//! close 由 stop 标志驱动。⚠️ 真事件 + 读取正确性待 **linuxvm 真机验证**（见文末 TODO）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const dm = @import("dns_monitor.zig");
const params = @import("network_params.zig");

const DnsSettings = dm.DnsSettings;
const Callback = dm.Callback;

const is_linux = builtin.os.tag == .linux and builtin.abi != .android;

const MaxSubscribers: usize = 16;
const Subscriber = struct { cb: Callback, ctx: ?*anyopaque };

/// DNS 服务器上限：对齐 network.zig MAX_DNS_SERVERS（8），保证与门面快照一致。
const MaxDnsServers: usize = 8;

const ResolvPath = "/etc/resolv.conf";

// ---- inotify 常量（linux/inotify.h 权威值）----
const IN_ATTRIB: u32 = 0x00000004;
const IN_CLOSE_WRITE: u32 = 0x00000008;
const IN_MOVED_TO: u32 = 0x00000080;
const IN_DELETE: u32 = 0x00000200; // 目录 watch 子项删除；文件 watch 用 IN_DELETE_SELF
const IN_DELETE_SELF: u32 = 0x00000400;
const IN_MOVE_SELF: u32 = 0x00000800;
const IN_IGNORED: u32 = 0x00008000; // watch 被内核移除（文件被删/替换）
// inotify_init1 标志：IN_NONBLOCK=O_NONBLOCK(0x800)、IN_CLOEXEC=O_CLOEXEC(0x80000)
const IN_NONBLOCK: u32 = 0x00000800;
const IN_CLOEXEC: u32 = 0x00080000;
/// 本文件对 resolv.conf 的敏感蒙版（任务指定）；ANY 事件另含 *_SELF/IN_IGNORED 用于重挂。
const WatchMask: u32 = IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE | IN_ATTRIB;

const InotifyEventHdr = extern struct {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
};

/// 事件缓冲是否含「需重挂」事件（IN_IGNORED 或 *SELF：inode 级删除/自身移动/被替换）。
fn hasReArmEvent(buf: []const u8) bool {
    var off: usize = 0;
    while (off + @sizeOf(InotifyEventHdr) <= buf.len) {
        const hdr: *align(1) const InotifyEventHdr = @ptrCast(buf.ptr + off);
        const mask = hdr.mask;
        const ev_len = hdr.len;
        if (ev_len == 0) {
            off += @sizeOf(InotifyEventHdr);
        } else {
            off += @sizeOf(InotifyEventHdr) + ev_len;
        }
        if ((mask & (IN_IGNORED | IN_DELETE_SELF | IN_MOVE_SELF)) != 0) return true;
    }
    return false;
}

const libc = struct {
    extern "c" fn inotify_init1(flags: c_int) c_int;
    extern "c" fn inotify_add_watch(fd: c_int, path: [*:0]const u8, mask: u32) c_int;
};

/// 后台 stat mtime 兜底节流：1s（resolv.conf 低频变化，rename 替换检测延迟 ≤ ~1s）。
const StatBackstopMs: i64 = 1000;

/// 后台 inotify + mtime 兜底驱动的 DNS 监测器（linux 桌面/服务器）。
pub const Impl = struct {
    allocator: std.mem.Allocator,
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// 共享锁：保护 buf/current + 订阅者注册表。
    mutex: zf.sync.Mutex = .{},
    buf: [MaxDnsServers]zf.net.IpAddr = undefined,
    buf_count: usize = 0,
    current: DnsSettings = .{},
    snapshot_ready: bool = false,
    subs: [MaxSubscribers]Subscriber = undefined,
    sub_count: usize = 0,
    emit_scratch: [MaxSubscribers]Subscriber = undefined,

    pub fn init(allocator: std.mem.Allocator) !Impl {
        _ = builtin; // 显式引用：本文件仅 linux 目标编译
        return .{ .allocator = allocator };
    }

    /// 启动后台 inotify 监测线程（幂等）。
    pub fn start(self: *Impl) !void {
        if (self.started.swap(true, .acq_rel)) return;
        if (comptime !is_linux) return;
        self.stop.store(false, .release);
        self.refresh(false); // 基线：先读一次当前值（不 emit），使 snapshot 立即可用
        self.thread = try std.Thread.spawn(.{}, monitorLoop, .{self});
        std.log.info("[dns] linux monitor started path={s}", .{ResolvPath});
    }

    pub fn subscribe(self: *Impl, cb: Callback, ctx: ?*anyopaque) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sub_count >= MaxSubscribers) {
            std.log.warn("[dns] subscriber registry full ({d}), subscribe ignored", .{MaxSubscribers});
            return error.TooManySubscribers;
        }
        self.subs[self.sub_count] = .{ .cb = cb, .ctx = ctx };
        self.sub_count += 1;
    }

    /// 当前系统 DNS 快照；未 start / 从未成功读取时 null。
    pub fn snapshot(self: *Impl) ?DnsSettings {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.snapshot_ready) return null;
        return self.current;
    }

    /// 停止后台线程（幂等）：置 stop 标志并 join。
    pub fn close(self: *Impl) void {
        self.started.store(false, .release);
        if (self.thread) |t| {
            self.stop.store(true, .release);
            t.join();
            self.thread = null;
            std.log.debug("[dns] linux monitor stopped", .{});
        }
    }

    pub fn deinit(self: *Impl) void {
        self.close();
    }

    // ---- 后台线程 ----

    fn monitorLoop(self: *Impl) void {
        // 后台线程专用单线程 io：blocking stat 就地执行（同 hosts_monitor pollLoop）。
        var threaded: std.Io.Threaded = .init_single_threaded;
        defer threaded.deinit();
        const io = threaded.io();

        const inotify_fd = libc.inotify_init1(@intCast(IN_NONBLOCK | IN_CLOEXEC));
        if (inotify_fd < 0) {
            std.log.warn("[dns] linux monitor: inotify_init1 failed, disabled", .{});
            return;
        }
        defer _ = std.c.close(inotify_fd);

        // resolv.conf 缺失（尚无 watch）属合法：mtime 兜底会在文件出现时重挂 + 触发。
        var wd = addResolvWatch(inotify_fd);
        if (wd < 0) {
            std.log.debug("[dns] linux monitor: {s} not present yet, mtime backstop will pick it up", .{ResolvPath});
        }
        var last_mtime = statResolvMtime(io);
        var need_refresh = false;
        var last_stat_ms: i64 = 0;

        var pfd = [_]std.c.pollfd{.{ .fd = inotify_fd, .events = std.c.POLL.IN, .revents = 0 }};
        while (!self.stop.load(.acquire)) {
            const rc = std.c.poll(&pfd, 1, 100);
            if (rc < 0) {
                if (std.c.errno(rc) == std.posix.E.INTR) continue;
                break;
            }
            if (rc > 0) {
                // fd 上只有本文件一个 watch：任一事件都可能是 DNS 变化；含 *_SELF/
                // IN_IGNORED 时需重挂（文件被替换/删除后 watch 已失效）。
                var buf: [4096]u8 = undefined;
                const n = std.c.read(inotify_fd, &buf, buf.len);
                if (n > 0) {
                    need_refresh = true;
                    if (hasReArmEvent(buf[0..@intCast(n)])) wd = -1;
                }
            }
            // 事件后无条件尝试重挂（idempotent：inode 未变返回原 wd，被替换则 watch 新 inode）。
            if (wd < 0) wd = addResolvWatch(inotify_fd);

            // mtime diff 兜底：节流 ~1s，覆盖 inotify 失效窗口（rename 替换 / 新建）。
            const now_ms = zf.platform.monoMillis();
            if (now_ms - last_stat_ms >= StatBackstopMs) {
                last_stat_ms = now_ms;
                const mt = statResolvMtime(io);
                if (mtimeChanged(last_mtime, mt)) {
                    last_mtime = mt;
                    need_refresh = true;
                }
            }

            if (need_refresh) {
                need_refresh = false;
                std.log.info("[dns] linux: {s} changed (inotify or mtime)", .{ResolvPath});
                self.refresh(true);
            }
        }
    }

    /// 重读当前 DNS → diff →（可选）emit。在后台线程/start 同步调用。
    fn refresh(self: *Impl, do_emit: bool) void {
        var fetched: [MaxDnsServers]zf.net.IpAddr = undefined;
        const fetched_slice = params.queryDnsServers(&fetched);

        self.mutex.lock();
        const changed = !ipListEqual(self.current.servers, fetched_slice);
        if (changed) {
            if (fetched_slice.len > 0) @memcpy(self.buf[0..fetched_slice.len], fetched_slice);
            self.buf_count = fetched_slice.len;
            self.current = .{ .servers = self.buf[0..self.buf_count] };
        }
        self.snapshot_ready = true;
        self.mutex.unlock();

        if (changed and do_emit) self.emit();
    }

    fn emit(self: *Impl) void {
        self.mutex.lock();
        const n = self.sub_count;
        if (n > 0) @memcpy(self.emit_scratch[0..n], self.subs[0..n]);
        self.mutex.unlock();
        for (self.emit_scratch[0..n]) |s| s.cb(&self.current, s.ctx);
    }
};

/// 对 /etc/resolv.conf 挂 watch；失败（文件缺失等）返回 <0。
fn addResolvWatch(fd: c_int) c_int {
    var path_z: [std.fs.max_path_bytes:0]u8 = undefined;
    if (ResolvPath.len >= path_z.len) return -1;
    @memcpy(path_z[0..ResolvPath.len], ResolvPath);
    path_z[ResolvPath.len] = 0;
    return libc.inotify_add_watch(fd, &path_z, WatchMask);
}

/// stat resolv.conf mtime（纳秒）；文件缺失/不可读返回 null。
fn statResolvMtime(io: std.Io) ?i128 {
    const st = std.Io.Dir.cwd().statFile(io, ResolvPath, .{}) catch return null;
    return @intCast(st.mtime.nanoseconds);
}

/// mtime 兜底比较：null 表示文件缺失；null↔值转变也算变化。
fn mtimeChanged(a: ?i128, b: ?i128) bool {
    if (a == null or b == null) return a != b;
    return a.? != b.?;
}

/// 去重比较：两 IP 列表逐地址判等（顺序敏感：DNS 服务器顺序有意义）。
pub fn ipListEqual(a: []const zf.net.IpAddr, b: []const zf.net.IpAddr) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (!ipEqual(x, y)) return false;
    }
    return true;
}

/// IpAddr 判等（union(enum) 载荷为数组，避免依赖 == 合成；同 mod.zig ipEqual）。
fn ipEqual(a: zf.net.IpAddr, b: zf.net.IpAddr) bool {
    return switch (a) {
        .v4 => |x| switch (b) {
            .v4 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
        .v6 => |x| switch (b) {
            .v6 => |y| std.mem.eql(u8, &x, &y),
            else => false,
        },
    };
}

// ============================================================
// 单元测试（仅 linux 目标编译并运行；纯 diff/解析不依赖 OS 事件源）
// ============================================================

const testing = std.testing;

test "dns_monitor_linux: ipListEqual 去重语义" {
    if (comptime !is_linux) return error.SkipZigTest;
    const a = [_]zf.net.IpAddr{ .{ .v4 = .{ 223, 5, 5, 5 } }, .{ .v4 = .{ 8, 8, 8, 8 } } };
    const same = [_]zf.net.IpAddr{ .{ .v4 = .{ 223, 5, 5, 5 } }, .{ .v4 = .{ 8, 8, 8, 8 } } };
    const reordered = [_]zf.net.IpAddr{ .{ .v4 = .{ 8, 8, 8, 8 } }, .{ .v4 = .{ 223, 5, 5, 5 } } };
    try testing.expect(ipListEqual(&a, &same));
    try testing.expect(!ipListEqual(&a, &reordered)); // 顺序敏感
    try testing.expect(!ipListEqual(&a, &.{}));
}

test "dns_monitor_linux: lifecycle 启停幂等 + snapshot 就绪" {
    if (comptime !is_linux) return error.SkipZigTest;
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();

    try testing.expect(mon.snapshot() == null); // 未 start → null

    try mon.start();
    try mon.start(); // 幂等
    try testing.expect(mon.thread != null);
    try testing.expect(mon.snapshot() != null); // start 同步基线 → 就绪

    mon.close();
    mon.close(); // 幂等
    try testing.expect(mon.thread == null);
}

test "dns_monitor_linux: 真读系统 DNS 返回格式正确快照" {
    // 端到端：queryDnsServers 真读 /etc/resolv.conf，不依赖事件。
    if (comptime !is_linux) return error.SkipZigTest;
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();

    var local: [MaxDnsServers]zf.net.IpAddr = undefined;
    const real = params.queryDnsServers(&local);
    if (real.len == 0) return; // 无 nameserver：合法，跳过断言

    try mon.start();
    defer mon.close();
    const got = mon.snapshot() orelse return error.SkipZigTest;
    try testing.expectEqual(real.len, got.servers.len);
    for (got.servers) |ip| switch (ip) {
        .v4 => |v| try testing.expectEqual(@as(usize, 4), v.len),
        .v6 => |v| try testing.expectEqual(@as(usize, 16), v.len),
    };
    try testing.expect(ipListEqual(real, got.servers));
}

test "dns_monitor_linux: mtimeChanged 空值语义" {
    if (comptime !is_linux) return error.SkipZigTest;
    try testing.expect(!mtimeChanged(null, null)); // 都在缺失态
    try testing.expect(mtimeChanged(null, @as(?i128, 42)));
    try testing.expect(mtimeChanged(@as(?i128, 42), null)); // 文件被删 → 变化
    try testing.expect(!mtimeChanged(@as(?i128, 42), @as(?i128, 42)));
    try testing.expect(mtimeChanged(@as(?i128, 42), @as(?i128, 43)));
}

// TODO(linuxvm 真机验证)：
//  1. 改 /etc/resolv.conf nameserver（写后关闭 / systemd-resolved 原子替换两种）
//     → 确认 inotify/mtime 兜底触发、snapshot 与新值一致、去重正确。
//  2. resolv.conf 缺失后由 DNS 工具重建（新建 inode）→ mtime 兜底 + 重挂 watch 恢复。
