//! real_event_harness — Tier2 VM 真事件订阅 harness（测试工具二进制，非生产路径）
//!
//! 订阅 zignetmon Monitor 门面的「网络变了」粗回调，每收到一次即向 **stdout** 打印一行：
//!
//!     CHANGED iface=<默认出口接口 index 或 null> gw=<网关 IP 或 ->
//!
//! 供 VM 真事件测试脚本（macvm / linuxvm / windowsvm，design.md §6 Tier2）解析断言：
//! 触发真实 OS 网络变化（route / DNS / 代理 / hosts）后，在运行窗口内应出现 ≥1 行
//! CHANGED（消费方恰好收到一次粗回调的验收准则）。
//!
//! 用法：real_event [运行秒数]        （argv[1] 省略默认 30）
//! 行为：Monitor.init + start + subscribe → 运行满秒数 → close + deinit → 退出 0。
//!
//! 输出约定：
//!   - stdout：机器可解析的 CHANGED 行（逐行免缓冲直写，供脚本实时 tail）；
//!   - stderr：进程诊断（std.debug，仅错误/用法提示，非数据路径日志）。
//!
//! 依赖：zigfoundation（alloc / platform / net）+ zignetmon 库模块（Monitor 门面）。
//! 注意：本工具为订阅阻塞类二进制，仅用于 VM 真事件验证，不接入构建门禁与 zigtester
//! 常规套件（运行需手工触发 OS 网络变化）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const znetmon = @import("zignetmon");

/// 未给 argv[1] 时的默认运行秒数。
const DefaultRunSeconds: u32 = 30;

/// 回调在 network / hosts / proxy 各自后台线程触发，stdout 写须互斥串行（保证整行原子）。
var stdout_lock: zf.sync.Mutex = .{};

// ============================================================================
// 底层 stdout 写（测试工具专用同步 IO；免缓冲逐行实时，生产路径禁止此写法）
// 写法对齐 zigfoundation cli.zig 先例：POSIX std.c.write；Windows kernel32 WriteFile。
// ============================================================================

/// 将 bytes 完整写到 stdout（阻塞工具场景，忽略短写错误；返回时尽力已写完）。
fn writeStdoutAll(bytes: []const u8) void {
    if (builtin.os.tag == .windows) {
        // kernel32 极小子集（0.16 std 未覆盖），同 zigfoundation cli.zig。
        const Win32 = struct {
            const HANDLE = *anyopaque;
            const DWORD = u32;
            const BOOL = i32;
            const LPVOID = *anyopaque;
            const STD_OUTPUT_HANDLE: DWORD = @as(DWORD, @bitCast(@as(i32, -11)));
            extern "kernel32" fn GetStdHandle(nStdHandle: DWORD) callconv(.winapi) HANDLE;
            extern "kernel32" fn WriteFile(
                hFile: HANDLE,
                lpBuffer: [*]const u8,
                nNumberOfBytesToWrite: DWORD,
                lpNumberOfBytesWritten: ?*DWORD,
                lpOverlapped: ?LPVOID,
            ) callconv(.winapi) BOOL;
        };
        const h = Win32.GetStdHandle(Win32.STD_OUTPUT_HANDLE);
        _ = Win32.WriteFile(h, bytes.ptr, @intCast(bytes.len), null, null);
        return;
    }

    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.write(1, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return; // 写失败放弃（诊断够用即可，测试工具）
        off += @intCast(n);
    }
}

// ============================================================================
// 内存 sink writer（仅用于复用 net.IpAddr.format 的规范格式化，无真实 sink）
// ============================================================================

/// 短文本（网关 IP ≤ 39 字符）格式进 80 字节内存缓冲不会触发 drain，此回调仅为
/// 满足 std.Io.Writer.VTable 契约而存在（若触发则按常规消费缓冲计数，语义不关键）。
const sink_vtable: std.Io.Writer.VTable = .{ .drain = sinkDrain };

fn sinkDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const buffered = w.end;
    w.end = 0;
    var total: usize = buffered;
    for (data, 0..) |chunk, i| {
        const times: usize = if (i == data.len - 1) splat else 1;
        total += chunk.len * times;
    }
    return total;
}

// ============================================================================
// 订阅回调：每次粗回调向 stdout 打印一行 CHANGED（测试脚本解析断言源）
// ============================================================================

fn onNetworkChanged(snap: *const znetmon.Snapshot, _ctx: ?*anyopaque) void {
    _ = _ctx;
    stdout_lock.lock();
    defer stdout_lock.unlock();

    // 网关文本：复用 net.IpAddr.format 规范格式化到内存缓冲；缺省/失败为 "-"。
    var ip_buf: [80]u8 = undefined;
    var ip_w = std.Io.Writer{ .vtable = &sink_vtable, .buffer = &ip_buf, .end = 0 };
    const gw: []const u8 = if (snap.gateway) |g| blk: {
        g.format(&ip_w) catch break :blk "-";
        break :blk ip_buf[0..ip_w.end];
    } else "-";

    var line_buf: [160]u8 = undefined;
    // 行超长（不应发生）则丢弃本行
    const line = (if (snap.default_interface) |iface|
        std.fmt.bufPrint(&line_buf, "CHANGED iface={d} gw={s}\n", .{ iface.index, gw })
    else
        std.fmt.bufPrint(&line_buf, "CHANGED iface=null gw={s}\n", .{gw})) catch return;
    writeStdoutAll(line);
}

// ============================================================================
// 入口
// ============================================================================

pub fn main(init: std.process.Init) !void {
    zf.alloc.initFromEnv(init);
    const allocator = zf.alloc.gpa();

    // argv[1] = 运行秒数（省略默认 30；非正整数报用法退出 2）。
    var seconds: u32 = DefaultRunSeconds;
    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();
    _ = args_iter.skip(); // 程序名
    if (args_iter.next()) |arg| {
        seconds = std.fmt.parseInt(u32, arg, 10) catch {
            std.debug.print("[real_event] invalid run-seconds argument: {s}\n", .{arg});
            std.process.exit(2);
        };
    }
    if (seconds == 0) {
        std.debug.print("[real_event] run-seconds must be > 0\n", .{});
        std.process.exit(2);
    }

    var m = znetmon.Monitor.init(allocator, .{}) catch |err| {
        std.debug.print("[real_event] Monitor.init failed: {s}\n", .{@errorName(err)});
        return err;
    };
    defer m.deinit(); // close（join 线程）+ 释放；返回前确保回调不再产生

    znetmon.Monitor.subscribe(&m, onNetworkChanged, null) catch |err| {
        std.debug.print("[real_event] subscribe failed: {s}\n", .{@errorName(err)});
        return err;
    };
    m.start() catch |err| {
        std.debug.print("[real_event] Monitor.start failed: {s}\n", .{@errorName(err)});
        return err;
    };

    // 运行满秒数：100ms 检查间隔等待（监测在后台线程，禁忙等；睡眠经 zf.platform）。
    const end_ms = zf.platform.monoMillis() + @as(i64, seconds) * 1000;
    while (zf.platform.monoMillis() < end_ms) {
        zf.platform.sleepNs(100 * std.time.ns_per_ms);
    }

    // 至此退出 0；defer m.deinit() 完成线程回收与释放。
}
