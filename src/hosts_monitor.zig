//! hosts 文件变化监测（跨平台，单文件，不依赖 network）。
//!
//! 背景：hosts 文件（/etc/hosts 或 Windows 系统目录）是「域名 → IP」的本地静态映射，
//! 用户/杀毒/代理工具修改它会影响 DNS 解析结果。本模块轮询监测该文件，内容变化时
//! 以回调通知上层（mtime 纳秒时间戳）。
//!
//! 架构：后台线程每 5s（可调）对文件做一次 stat（mtime + size），与上次基线比对，
//! 仅当确实变化才 emit；空路径（iOS/Android，hosts 文件非本机用户可改）start 直接 no-op。
//!
//! 数据面说明：本模块是低频轮询监测（非代理数据热路径），允许后台线程 + 阻塞 stat，
//! 但禁止忙等 —— 每轮用 `zf.platform.sleepNs` 分片睡眠（非忙等）。
//!
//! 线程模型：`start` 幂等 spawn 单个后台线程（`std.Thread.spawn` + `std.atomic.Value(bool)`
//! stop 标志）；`close` 置 stop 并 join（幂等）。mtime 状态为 i128，超出 std 原子整数
//! 上限（64 位，Windows 目标不允许 128 位原子），因此与订阅者注册表共用 `zf.sync.Mutex`
//! 保护（低频访问，无竞争热点）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");

/// hosts 文件变化回调：mtime 为纳秒时间戳（i128）。
pub const Callback = *const fn (mtime: i128, ctx: ?*anyopaque) void;

/// 生产轮询间隔：5s（design.md §3/§5.2；findings：mihomo 懒轮询 + stat diff(5s)）。
const DefaultPollIntervalNs: u64 = 5 * std.time.ns_per_s;

/// 睡眠分片：100ms。保证 close() 停线程延迟 ≤ ~100ms，同时非忙等。
const SleepTickNs: u64 = 100 * std.time.ns_per_ms;

/// 订阅者上限（回调注册表容量）。hosts 监测属低频事件，实际消费者通常仅门面 1 个。
const MaxSubscribers: usize = 16;

/// 单个订阅者（回调 + 不透明上下文）。
const Subscriber = struct {
    cb: Callback,
    ctx: ?*anyopaque,
};

/// 返回各平台 hosts 文件默认绝对路径。
///
/// - POSIX 桌面/服务器（macOS/Linux/…）：`/etc/hosts`
/// - Windows：`C:\Windows\System32\drivers\etc\hosts`
/// - iOS/Android：返回空串 = 无 hosts 监测（移动端 hosts 受沙箱/SEAndroid 保护，
///   非用户可改，监测无意义 → `start` no-op）。
pub fn defaultHostsPath() []const u8 {
    // 注：Zig 中 Android 无独立 os.tag，以 linux + android ABI 表示。
    if (builtin.os.tag == .linux and builtin.abi == .android) return "";
    return switch (builtin.os.tag) {
        .windows => "C:\\Windows\\System32\\drivers\\etc\\hosts",
        .ios, .tvos, .watchos, .visionos => "",
        else => "/etc/hosts",
    };
}

pub const HostsMonitor = struct {
    allocator: std.mem.Allocator,
    /// dup 的 hosts 文件绝对路径；空串 = no-op 平台。
    path: []u8,
    /// 幂等 start 标志（真值 = start 已被调用，无论是否真正建线程）。
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// stop 请求标志：close() 置位，后台线程退出。
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// 后台轮询线程（未启动/已关闭时为 null）。
    thread: ?std.Thread = null,
    /// 轮询间隔（纳秒）。生产 5s；单元测试直接下调以加速。
    poll_interval_ns: u64 = DefaultPollIntervalNs,
    /// 共享锁：保护「mtime/size 基线 + 订阅者注册表」。低频访问（每轮 stat 一次），
    /// 无竞争热点；i128 mtime 无法用 std 原子（Windows 目标禁 128 位原子），故走互斥锁。
    mutex: zf.sync.Mutex = .{},
    /// 最近一次成功 stat 观测到的文件 mtime（纳秒）；null = 尚未观测（基线未建立）。
    last_mtime: ?i128 = null,
    /// 变更检测的 size 基线。
    last_size: u64 = 0,
    /// 订阅者注册表（回调链表语义）。
    subs: [MaxSubscribers]Subscriber = undefined,
    sub_count: usize = 0,
    /// emit 快照缓冲：先拷出注册表快照、再锁外回调，避免持锁调用用户回调导致重入死锁。
    /// 仅轮询线程（单生产者）写入。
    emit_scratch: [MaxSubscribers]Subscriber = undefined,

    /// 创建监测器：`path` 由本结构体 dup（生命周期由 deinit 释放）。
    pub fn init(allocator: std.mem.Allocator, path: []const u8) !HostsMonitor {
        return .{
            .allocator = allocator,
            .path = try allocator.dupe(u8, path),
        };
    }

    /// 启动后台轮询线程（幂等）。空路径（iOS/Android）为 no-op，直接返回不建线程。
    pub fn start(self: *HostsMonitor) !void {
        if (self.started.swap(true, .acq_rel)) return; // 幂等：已启动不再建线程
        if (self.path.len == 0) {
            std.log.debug("[hosts] empty path (mobile no-op), monitor disabled", .{});
            return;
        }
        self.thread = try std.Thread.spawn(.{}, pollLoop, .{self});
        std.log.info("[hosts] monitoring started path={s}", .{self.path});
    }

    /// 订阅 hosts 变化。回调在后台轮询线程上触发，应尽快返回、不得阻塞。
    pub fn subscribe(self: *HostsMonitor, cb: Callback, ctx: ?*anyopaque) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sub_count >= MaxSubscribers) {
            std.log.warn("[hosts] subscriber registry full ({d}), subscribe ignored", .{MaxSubscribers});
            return error.TooManySubscribers;
        }
        self.subs[self.sub_count] = .{ .cb = cb, .ctx = ctx };
        self.sub_count += 1;
        std.log.debug("[hosts] subscriber added total={d}", .{self.sub_count});
    }

    /// 最近观测到的文件 mtime（纳秒）；尚未观测到（文件一直不可读）时为 null。
    /// 线程安全（互斥锁保护）。注意：首次观测建立基线不发事件，lastMtime 仍会返回该值。
    pub fn lastMtime(self: *HostsMonitor) ?i128 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.last_mtime;
    }

    /// 停止后台线程（幂等）：置 stop 标志并 join；join 延迟 ≤ ~100ms（分片睡眠）。
    pub fn close(self: *HostsMonitor) void {
        self.started.store(false, .release); // 允许 close 后再 start
        if (self.thread) |t| {
            self.stop.store(true, .release);
            t.join();
            self.thread = null;
            std.log.debug("[hosts] monitor stopped", .{});
        }
    }

    /// 释放资源：先停线程（幂等，内部处理未 close 情形），再释放 dup 的 path。
    pub fn deinit(self: *HostsMonitor) void {
        self.close();
        self.allocator.free(self.path);
        self.path = &.{};
    }

    // ---- 后台轮询线程 ----

    fn pollLoop(self: *HostsMonitor) void {
        // 后台线程专用单线程 io：阻塞 stat 就地执行，无需外部注入 Io 实例。
        var threaded: std.Io.Threaded = .init_single_threaded;
        defer threaded.deinit();
        const io = threaded.io();

        var slept_ns: u64 = 0;
        while (true) {
            // 分片睡眠（非忙等）：每片 100ms，同时保证 stop 及时响应。
            zf.platform.sleepNs(SleepTickNs);
            if (self.stop.load(.acquire)) return;
            slept_ns += SleepTickNs;
            if (slept_ns < self.poll_interval_ns) continue;
            slept_ns = 0;
            self.pollOnce(io);
        }
    }

    /// 单轮 stat diff：mtime + size 任一变化才 emit。每次成功 stat 都会刷新
    /// last_mtime（供上层 snapshot 读取当前文件状态），仅「相对上次变化」时发事件。
    fn pollOnce(self: *HostsMonitor, io: std.Io) void {
        const st = std.Io.Dir.cwd().statFile(io, self.path, .{}) catch |err| {
            // 文件暂不可读（不存在/权限/正在被替换）：保留上次状态，等下一轮。
            std.log.debug("[hosts] statFile failed err={s} path={s}", .{ @errorName(err), self.path });
            return;
        };
        const mtime: i128 = @intCast(st.mtime.nanoseconds);

        var changed = false;
        self.mutex.lock();
        if (self.last_mtime) |prev| {
            // 已有基线：mtime 或 size 任一变化即视为内容变化。
            changed = (mtime != prev) or (st.size != self.last_size);
        } else {
            std.log.debug("[hosts] baseline established mtime={d} size={d}", .{ mtime, st.size });
        }
        // 无论是否变化都刷新基线（供上层 snapshot 读取当前文件状态）。
        self.last_mtime = mtime;
        self.last_size = st.size;
        self.mutex.unlock();

        if (changed) {
            std.log.info("[hosts] hosts file changed mtime={d} size={d}", .{ mtime, st.size });
            self.emit(mtime);
        }
    }

    /// 分发事件给全部订阅者：先持锁把注册表拷到快照缓冲，再解锁逐条回调，
    /// 避免在用户回调执行期间持锁（回调可能重入 subscribe 造成非递归锁死锁）。
    fn emit(self: *HostsMonitor, mtime: i128) void {
        self.mutex.lock();
        const n = self.sub_count;
        if (n > 0) @memcpy(self.emit_scratch[0..n], self.subs[0..n]);
        self.mutex.unlock();
        for (self.emit_scratch[0..n]) |s| s.cb(mtime, s.ctx);
    }
};

// ============================================================
// 单元测试
// ============================================================

const testing = std.testing;
const Allocator = std.mem.Allocator;

/// 测试上下文：回调经 ctx 写入触发标志与 mtime。跨线程读写在回调线程
/// （HostsMonitor 后台线程）与测试主线程间进行，故同样用互斥锁保护
/// （i128 不能用 std 原子）。
const TestCtx = struct {
    mutex: zf.sync.Mutex = .{},
    fired: bool = false,
    mtime: i128 = 0,
};

fn onHostsChange(mtime: i128, ctx: ?*anyopaque) void {
    const c: *TestCtx = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    c.mtime = mtime;
    c.fired = true;
}

/// 在系统临时目录建 hosts 文件，返回 TmpDir 与文件的绝对路径。
const TmpHosts = struct { tmp: testing.TmpDir, path: []u8 };

fn makeTmpHosts(io: std.Io, allocator: Allocator, content: []const u8) !TmpHosts {
    var tmp = testing.tmpDir(.{});
    errdefer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "hosts", .data = content });

    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try std.Io.Dir.realPath(tmp.parent_dir, io, &buf);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}/hosts", .{ buf[0..n], tmp.sub_path });
    errdefer allocator.free(path);
    return .{ .tmp = tmp, .path = path };
}

/// 轮询等待（10ms 步进，非忙等）直至谓词为真或超时，返回是否达成。
fn waitUntil(pred: *const fn (?*anyopaque) bool, ctx: ?*anyopaque, timeout_ns: u64) bool {
    var waited: u64 = 0;
    while (waited < timeout_ns) : (waited += 10 * std.time.ns_per_ms) {
        if (pred(ctx)) return true;
        zf.platform.sleepNs(10 * std.time.ns_per_ms);
    }
    return pred(ctx);
}

/// 谓词：HostsMonitor 已建立基线（首次成功 stat）。
fn baselineReady(mon_ptr: ?*anyopaque) bool {
    const mon: *HostsMonitor = @ptrCast(@alignCast(mon_ptr.?));
    return mon.lastMtime() != null;
}

/// 谓词：TestCtx 收到回调。
fn firedFlag(ctx: ?*anyopaque) bool {
    const c: *TestCtx = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    return c.fired;
}

test "hosts_monitor: defaultHostsPath 平台默认路径正确" {
    const p = defaultHostsPath();
    // 仅本机（host）可运行的断言；其余分支由交叉编译覆盖面保证逻辑正确。
    if (builtin.os.tag == .linux and builtin.abi == .android) {
        try testing.expectEqualStrings("", p);
    } else switch (builtin.os.tag) {
        .windows => try testing.expectEqualStrings("C:\\Windows\\System32\\drivers\\etc\\hosts", p),
        .ios, .tvos, .watchos, .visionos => try testing.expectEqualStrings("", p),
        else => try testing.expectEqualStrings("/etc/hosts", p),
    }
}

test "hosts_monitor: init/start/close/deinit 生命周期（线程启停幂等）" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var hosts = try makeTmpHosts(io, testing.allocator, "127.0.0.1 localhost\n");
    defer hosts.tmp.cleanup();
    defer testing.allocator.free(hosts.path);

    var mon = try HostsMonitor.init(testing.allocator, hosts.path);
    defer mon.deinit();
    mon.poll_interval_ns = 20 * std.time.ns_per_ms;

    // 基线未建立 → lastMtime null
    try testing.expect(mon.lastMtime() == null);

    // start 幂等：重复调用不重复建线程
    try mon.start();
    try mon.start();
    try testing.expect(mon.thread != null);

    // close 幂等
    mon.close();
    mon.close();
    try testing.expect(mon.thread == null);

    // close 后可再 start（线程可复用）
    try mon.start();
    try testing.expect(mon.thread != null);
    mon.close();
    try testing.expect(mon.thread == null);
}

test "hosts_monitor: 空路径（移动 no-op）start 不建线程" {
    var mon = try HostsMonitor.init(testing.allocator, "");
    defer mon.deinit();
    try mon.start();
    try testing.expect(mon.thread == null); // no-op：不建后台线程
    try testing.expect(mon.lastMtime() == null);
    mon.close();
}

test "hosts_monitor: hosts 内容变化触发 stat diff 回调" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var hosts = try makeTmpHosts(io, testing.allocator, "127.0.0.1 localhost\n");
    defer hosts.tmp.cleanup();
    defer testing.allocator.free(hosts.path);

    var ctx = TestCtx{};
    var mon = try HostsMonitor.init(testing.allocator, hosts.path);
    defer mon.deinit();
    mon.poll_interval_ns = 40 * std.time.ns_per_ms; // 测试下调轮询间隔

    try mon.subscribe(onHostsChange, &ctx);
    try mon.start();

    // 等待基线建立（首次成功 stat，不发事件）
    try testing.expect(waitUntil(baselineReady, @ptrCast(&mon), 2 * std.time.ns_per_s));
    ctx.mutex.lock();
    const fired_before = ctx.fired;
    ctx.mutex.unlock();
    try testing.expect(!fired_before); // 基线不触发回调

    // 写入不同内容（长度不同 → size 变化必被 stat diff 捕获），触发回调
    const changed_content = "127.0.0.1 localhost\n192.0.2.1 example.test\n10.0.0.1 internal.local\n";
    try hosts.tmp.dir.writeFile(io, .{ .sub_path = "hosts", .data = changed_content });

    try testing.expect(waitUntil(firedFlag, @ptrCast(&ctx), 2 * std.time.ns_per_s));

    ctx.mutex.lock();
    const fired_mtime = ctx.mtime;
    ctx.mutex.unlock();
    try testing.expect(fired_mtime > 0);
    try testing.expectEqual(fired_mtime, mon.lastMtime().?); // 回调 mtime = 快照 mtime
}

test "hosts_monitor: lastMtime 随内容变化刷新" {
    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

    var hosts = try makeTmpHosts(io, testing.allocator, "127.0.0.1 localhost\n");
    defer hosts.tmp.cleanup();
    defer testing.allocator.free(hosts.path);

    var mon = try HostsMonitor.init(testing.allocator, hosts.path);
    defer mon.deinit();
    mon.poll_interval_ns = 30 * std.time.ns_per_ms;

    try mon.start();
    try testing.expect(waitUntil(baselineReady, @ptrCast(&mon), 2 * std.time.ns_per_s)); // 等基线
    const before = mon.lastMtime().?;
    try testing.expect(before > 0);

    // 改内容后 lastMtime 最终刷新为新值（即使本轮因 mtime 粒度接近也由 size 保证）
    try hosts.tmp.dir.writeFile(io, .{ .sub_path = "hosts", .data = "::1 localhost ip6-localhost\n" });

    // 等待 mtime 变化（轮询刷新 lastMtime，最多等 2s）
    var waited: u64 = 0;
    var refreshed = false;
    while (waited < 2 * std.time.ns_per_s) : (waited += 20 * std.time.ns_per_ms) {
        if (mon.lastMtime().? != before) {
            refreshed = true;
            break;
        }
        zf.platform.sleepNs(20 * std.time.ns_per_ms);
    }
    try testing.expect(refreshed);
}
