//! 系统代理变化监测 — macOS 后端（design.md §5.3）。
//!
//! 事件源：**SystemConfiguration / SCDynamicStore** 的全局代理 key
//! `State:/Network/Global/Proxies`。configd 在系统代理被修改时更新该 key 并通知
//! 订阅者（对标 sing-box proxy_darwin + Apple 推荐做法）。变化 → 后台 CFRunLoop
//! 线程触发 callout → SCDynamicStoreCopyProxies 重读当前值 → diff → emit。
//!
//! 实现方式：**运行时 dlopen + dlsym** 解析 SystemConfiguration / CoreFoundation 符号
//! （不引入 framework 链接依赖；@extern/mach symbol 解析先例见 zignetmon.network）。符号解析
//! 在 init 时完成一次，解析失败（极端环境缺 framework）→ start no-op + snapshot null。
//!
//! iOS：同一 darwin 文件分发（design 语义 stub），但 SCDynamicStore 对沙箱 app 不可用，
//! 因此内部 `if (comptime !is_macos)` 恒 no-op（不建线程、不解析符号）。
//!
//! 数据面说明：低频事件监测（非代理热路径），允许后台线程 + 阻塞 CFRunLoop 等待
//! （非忙等）。事件回调在 CFRunLoop 线程触发，应尽快返回。
//!
//! ProxySettings 语义与 dispatcher 一致：仅显式代理（HTTP/HTTPS/SOCKS host:port）
//! 视为 enabled；仅 PAC（ProxyAutoConfigEnable / WPAD）→ disabled（记 debug）。

const std = @import("std");
const builtin = @import("builtin");
const zf = @import("zigfoundation");
const pm = @import("proxy_monitor.zig");

const ProxySettings = pm.ProxySettings;
const Callback = pm.Callback;

const is_macos = builtin.os.tag == .macos;

const MaxSubscribers: usize = 16;
const Subscriber = struct { cb: Callback, ctx: ?*anyopaque };

// ---- CoreFoundation / SystemConfiguration 类型 ----
const CFTypeRef = ?*anyopaque;
const CFAllocatorRef = ?*const anyopaque;

// ---- C 运行时（动态符号解析）----
const dl = struct {
    extern "c" fn dlopen(path: [*:0]const u8, mode: c_int) ?*anyopaque;
    extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
};
const RTLD_LAZY: c_int = 1;

// CF 常量（不猜值）
const kCFStringEncodingASCII: u32 = 0x0600;
const kCFNumberSInt32Type: u64 = 3;

const SYSCONF_PATH = "/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration";
const COREFOUNDATION_PATH = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";

const ProxiesKey = "State:/Network/Global/Proxies";

/// SCDynamicStoreCallBack：系统代理 key 变化时在 CFRunLoop 线程被调用。
const SCDynCallout = *const fn (store: CFTypeRef, changed_keys: CFTypeRef, info: ?*anyopaque) callconv(.c) void;

/// SCDynamicStoreContext（info 承载 Impl 指针；create 时整结构被拷贝）。
const SCDynamicStoreContext = extern struct {
    version: isize,
    info: ?*anyopaque,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copy_description: ?*const anyopaque,
};

/// 解析得到的函数表（每条为一个 callconv(.c) fn 指针）。
const Sys = struct {
    // SystemConfiguration
    sc_create: *const fn (alloc: CFAllocatorRef, name: CFTypeRef, callout: SCDynCallout, ctx: ?*const anyopaque) callconv(.c) CFTypeRef,
    sc_copy_proxies: *const fn (store: CFTypeRef) callconv(.c) CFTypeRef,
    sc_set_notif: *const fn (store: CFTypeRef, keys: CFTypeRef, patterns: CFTypeRef) callconv(.c) bool,
    sc_mk_rls: *const fn (alloc: CFAllocatorRef, store: CFTypeRef, order: isize) callconv(.c) CFTypeRef,
    // CoreFoundation
    cf_release: *const fn (cf: CFTypeRef) callconv(.c) void,
    cf_mk_string: *const fn (alloc: CFAllocatorRef, cstr: [*:0]const u8, enc: u32) callconv(.c) CFTypeRef,
    cf_array_create: *const fn (alloc: CFAllocatorRef, values: [*]const CFTypeRef, count: isize, callbacks: ?*const anyopaque) callconv(.c) CFTypeRef,
    cf_dict_get_value: *const fn (dict: CFTypeRef, key: CFTypeRef) callconv(.c) CFTypeRef,
    cf_get_type_id: *const fn (cf: CFTypeRef) callconv(.c) u64,
    cf_string_tid: *const fn () callconv(.c) u64,
    cf_boolean_tid: *const fn () callconv(.c) u64,
    cf_number_tid: *const fn () callconv(.c) u64,
    cf_boolean_get_value: *const fn (cf: CFTypeRef) callconv(.c) bool,
    cf_number_get_value: *const fn (cf: CFTypeRef, t: u64, value: *anyopaque) callconv(.c) bool,
    cf_string_get_length: *const fn (cf: CFTypeRef) callconv(.c) isize,
    cf_string_get_cstring: *const fn (cf: CFTypeRef, buf: [*]u8, sz: isize, enc: u32) callconv(.c) bool,
    // CFRunLoop
    cf_rl_get_current: *const fn () callconv(.c) CFTypeRef,
    cf_rl_add_source: *const fn (rl: CFTypeRef, source: CFTypeRef, mode: CFTypeRef) callconv(.c) void,
    cf_rl_remove_source: *const fn (rl: CFTypeRef, source: CFTypeRef, mode: CFTypeRef) callconv(.c) void,
    cf_rl_run: *const fn () callconv(.c) void,
    cf_rl_stop: *const fn (rl: CFTypeRef) callconv(.c) void,
    // 仅测试用（合成 CF 字典 / CFBoolean 全局）
    cf_dict_create_mutable: *const fn (alloc: CFAllocatorRef, cap: isize, keycb: ?*const anyopaque, valcb: ?*const anyopaque) callconv(.c) CFTypeRef,
    cf_dict_add_value: *const fn (dict: CFTypeRef, key: CFTypeRef, value: CFTypeRef) callconv(.c) void,
    cf_number_create: *const fn (alloc: CFAllocatorRef, t: u64, value: *const anyopaque) callconv(.c) CFTypeRef,
    bool_true: CFTypeRef, // kCFBooleanTrue（解引用后的对象；测试用）
    bool_false: CFTypeRef,
};

fn lookupFn(handle: ?*anyopaque, comptime T: type, comptime name: [:0]const u8) ?T {
    const h = handle orelse return null;
    const sym = dl.dlsym(h, name.ptr) orelse return null;
    const addr: usize = @intFromPtr(sym);
    return @ptrFromInt(addr);
}

/// 运行时解析全部符号；任一关键符号缺失返回 null（start 将 no-op）。
///
/// 注意：struct 字段名不是 decl，不能用 `Sys.sc_create` 取「字段类型」——改用
/// `@TypeOf(s.sc_create)`（仅取字段类型、不读未初始化值）。
fn loadSys() ?Sys {
    if (!is_macos) return null;
    const sc_h = dl.dlopen(SYSCONF_PATH, RTLD_LAZY) orelse return null;
    const cf_h = dl.dlopen(COREFOUNDATION_PATH, RTLD_LAZY) orelse return null;
    var s: Sys = undefined;
    s.sc_create = lookupFn(sc_h, @TypeOf(s.sc_create), "SCDynamicStoreCreate") orelse return null;
    s.sc_copy_proxies = lookupFn(sc_h, @TypeOf(s.sc_copy_proxies), "SCDynamicStoreCopyProxies") orelse return null;
    s.sc_set_notif = lookupFn(sc_h, @TypeOf(s.sc_set_notif), "SCDynamicStoreSetNotificationKeys") orelse return null;
    s.sc_mk_rls = lookupFn(sc_h, @TypeOf(s.sc_mk_rls), "SCDynamicStoreCreateRunLoopSource") orelse return null;
    s.cf_release = lookupFn(cf_h, @TypeOf(s.cf_release), "CFRelease") orelse return null;
    s.cf_mk_string = lookupFn(cf_h, @TypeOf(s.cf_mk_string), "CFStringCreateWithCString") orelse return null;
    s.cf_array_create = lookupFn(cf_h, @TypeOf(s.cf_array_create), "CFArrayCreate") orelse return null;
    s.cf_dict_get_value = lookupFn(cf_h, @TypeOf(s.cf_dict_get_value), "CFDictionaryGetValue") orelse return null;
    s.cf_get_type_id = lookupFn(cf_h, @TypeOf(s.cf_get_type_id), "CFGetTypeID") orelse return null;
    s.cf_string_tid = lookupFn(cf_h, @TypeOf(s.cf_string_tid), "CFStringGetTypeID") orelse return null;
    s.cf_boolean_tid = lookupFn(cf_h, @TypeOf(s.cf_boolean_tid), "CFBooleanGetTypeID") orelse return null;
    s.cf_number_tid = lookupFn(cf_h, @TypeOf(s.cf_number_tid), "CFNumberGetTypeID") orelse return null;
    s.cf_boolean_get_value = lookupFn(cf_h, @TypeOf(s.cf_boolean_get_value), "CFBooleanGetValue") orelse return null;
    s.cf_number_get_value = lookupFn(cf_h, @TypeOf(s.cf_number_get_value), "CFNumberGetValue") orelse return null;
    s.cf_string_get_length = lookupFn(cf_h, @TypeOf(s.cf_string_get_length), "CFStringGetLength") orelse return null;
    s.cf_string_get_cstring = lookupFn(cf_h, @TypeOf(s.cf_string_get_cstring), "CFStringGetCString") orelse return null;
    s.cf_rl_get_current = lookupFn(cf_h, @TypeOf(s.cf_rl_get_current), "CFRunLoopGetCurrent") orelse return null;
    s.cf_rl_add_source = lookupFn(cf_h, @TypeOf(s.cf_rl_add_source), "CFRunLoopAddSource") orelse return null;
    s.cf_rl_remove_source = lookupFn(cf_h, @TypeOf(s.cf_rl_remove_source), "CFRunLoopRemoveSource") orelse return null;
    s.cf_rl_run = lookupFn(cf_h, @TypeOf(s.cf_rl_run), "CFRunLoopRun") orelse return null;
    s.cf_rl_stop = lookupFn(cf_h, @TypeOf(s.cf_rl_stop), "CFRunLoopStop") orelse return null;
    s.cf_dict_create_mutable = lookupFn(cf_h, @TypeOf(s.cf_dict_create_mutable), "CFDictionaryCreateMutable") orelse return null;
    s.cf_dict_add_value = lookupFn(cf_h, @TypeOf(s.cf_dict_add_value), "CFDictionaryAddValue") orelse return null;
    s.cf_number_create = lookupFn(cf_h, @TypeOf(s.cf_number_create), "CFNumberCreate") orelse return null;
    s.bool_true = cfBoolGlobal(cf_h, "kCFBooleanTrue");
    s.bool_false = cfBoolGlobal(cf_h, "kCFBooleanFalse");
    return s;
}

/// kCFBooleanTrue/False 导出的是「指向对象」的存储地址：先取存储再解引用得到对象。
fn cfBoolGlobal(cf_h: ?*anyopaque, comptime name: [:0]const u8) CFTypeRef {
    const h = cf_h orelse return null;
    const storage = dl.dlsym(h, name.ptr) orelse return null;
    const slot: *CFTypeRef = @ptrCast(@alignCast(storage));
    return slot.*;
}

/// 三个协议槽位 → 读取优先级 HTTP > HTTPS > SOCKS（取首个 enabled 且有 host 者）。
const ProtoSet = struct { enable: [:0]const u8, proxy: [:0]const u8, port: [:0]const u8 };
const protocols = [_]ProtoSet{
    .{ .enable = "HTTPEnable", .proxy = "HTTPProxy", .port = "HTTPPort" },
    .{ .enable = "HTTPSEnable", .proxy = "HTTPSProxy", .port = "HTTPSPort" },
    .{ .enable = "SOCKSEnable", .proxy = "SOCKSProxy", .port = "SOCKSPort" },
};

fn mkString(s: *const Sys, cstr: [:0]const u8) CFTypeRef {
    return s.cf_mk_string(null, cstr.ptr, kCFStringEncodingASCII);
}

/// 从 proxies 字典读显式代理；host 写入 host_buf（调用方生命周期内有效）。
/// 无法表示（仅 PAC / 无启用槽）→ disabled。
pub fn parseProxiesDict(s: *const Sys, dict: CFTypeRef, host_buf: []u8) ProxySettings {
    if (dict == null) return ProxySettings{};

    // PAC（自动配置脚本）是否存在 —— 仅用于「无显式代理时」的 debug 区分。
    var pac_seen = false;
    const pac_en_key = mkString(s, "ProxyAutoConfigEnable");
    defer release(s, pac_en_key);
    if (pac_en_key != null) {
        if (s.cf_dict_get_value(dict, pac_en_key)) |v| pac_seen = readBool(s, v);
    }

    for (protocols) |p| {
        const en_key = mkString(s, p.enable);
        defer release(s, en_key);
        const en_cf = if (en_key != null) s.cf_dict_get_value(dict, en_key) else null;
        if (en_cf == null) continue;
        if (!readBool(s, en_cf)) continue;

        const pr_key = mkString(s, p.proxy);
        defer release(s, pr_key);
        const host_cf = if (pr_key != null) s.cf_dict_get_value(dict, pr_key) else null;
        if (host_cf == null) continue;
        const host = readHost(s, host_cf, host_buf) orelse continue;

        var port: u16 = 0;
        const pt_key = mkString(s, p.port);
        defer release(s, pt_key);
        if (pt_key != null) {
            if (s.cf_dict_get_value(dict, pt_key)) |v| port = readPort(s, v);
        }
        return ProxySettings{ .enabled = true, .host = host, .port = port };
    }

    if (pac_seen) {
        std.log.debug("[proxy] mac: PAC-only system proxy, no host:port to report (disabled)", .{});
    }
    return ProxySettings{};
}

fn release(s: *const Sys, cf: CFTypeRef) void {
    if (cf != null) s.cf_release(cf);
}

/// 读布尔：macOS proxies 字典 *Enable 既可能是 CFBoolean 也可能是 CFNumber(0/1)
/// （实测无代理时系统写 CFNumber(0)）——两种类型都解析。
fn readBool(s: *const Sys, v: CFTypeRef) bool {
    if (v == null) return false;
    const tid = s.cf_get_type_id(v);
    if (tid == s.cf_boolean_tid()) return s.cf_boolean_get_value(v);
    if (tid == s.cf_number_tid()) {
        var i: i32 = 0;
        if (s.cf_number_get_value(v, kCFNumberSInt32Type, &i)) return i != 0;
    }
    return false;
}

fn readPort(s: *const Sys, v: CFTypeRef) u16 {
    if (v == null) return 0;
    if (s.cf_get_type_id(v) != s.cf_number_tid()) return 0;
    var p: i32 = 0;
    if (!s.cf_number_get_value(v, kCFNumberSInt32Type, &p)) return 0;
    if (p <= 0 or p > 65535) return 0;
    return @intCast(p);
}

/// 读 host CFString → host_buf；非字符串 / 超长 / 非 ASCII 返回 null。
fn readHost(s: *const Sys, v: CFTypeRef, host_buf: []u8) ?[]const u8 {
    if (v == null) return null;
    if (s.cf_get_type_id(v) != s.cf_string_tid()) return null;
    const raw_len = s.cf_string_get_length(v);
    if (raw_len <= 0) return null;
    const len: usize = @intCast(raw_len);
    if (len > host_buf.len) return null;
    if (!s.cf_string_get_cstring(v, host_buf.ptr, @intCast(host_buf.len), kCFStringEncodingASCII)) return null;
    const out = std.mem.sliceTo(host_buf[0..len], 0);
    if (out.len == 0) return null;
    return out;
}

fn settingsEqual(a: ProxySettings, b: ProxySettings) bool {
    if (a.enabled != b.enabled or a.port != b.port) return false;
    const ha = a.host orelse "";
    const hb = b.host orelse "";
    return std.mem.eql(u8, ha, hb);
}

// ============================================================
// Impl（与 dispatcher 契约一致：init/start/subscribe/snapshot/close/deinit）
// ============================================================

/// 系统代理变化监测器（macOS SCDynamicStore；iOS no-op）。
pub const Impl = struct {
    allocator: std.mem.Allocator,
    started: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,
    /// 共享锁：保护 current/host_buf + 订阅者注册表。
    mutex: zf.sync.Mutex = .{},
    current: ProxySettings = .{},
    host_buf: []u8 = &.{},
    snapshot_ready: bool = false,
    subs: [MaxSubscribers]Subscriber = undefined,
    sub_count: usize = 0,
    emit_scratch: [MaxSubscribers]Subscriber = undefined,
    // macOS SCDynamicStore 状态（dlopen 解析；iOS 不用）
    sys: ?Sys = null,
    store: CFTypeRef = null, // SCDynamicStoreRef
    source: CFTypeRef = null, // CFRunLoopSourceRef
    key_str: CFTypeRef = null, // 监听 key CFString
    name_str: CFTypeRef = null, // store 名 CFString
    mode_str: CFTypeRef = null, // "kCFRunLoopDefaultMode"
    /// 后台 CFRunLoop 引用（线程置位，close 经其停止）；0 = 未运行。
    rl_ref: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(allocator: std.mem.Allocator) !Impl {
        var mon = Impl{ .allocator = allocator };
        mon.sys = loadSys();
        if (mon.sys == null and is_macos) {
            std.log.warn("[proxy] mac monitor: SystemConfiguration/CoreFoundation symbols unresolvable", .{});
        }
        return mon;
    }

    /// 启动后台 CFRunLoop 监听线程（幂等）。
    pub fn start(self: *Impl) !void {
        if (self.started.swap(true, .acq_rel)) return;
        if (comptime !is_macos) {
            // iOS：SCDynamicStore 对沙箱 app 不可用，恒 no-op。
            std.log.debug("[proxy] mac monitor no-op on iOS", .{});
            return;
        }
        const s_val = self.sys orelse {
            std.log.warn("[proxy] mac monitor: not started (sys load failed)", .{});
            return;
        };
        const s: *const Sys = &s_val;

        // 建 store + 通知 key（configd 侧注册，无需运行循环即可生效）。
        self.key_str = mkString(s, ProxiesKey);
        if (self.key_str == null) {
            std.log.warn("[proxy] mac monitor: mkString(key) failed", .{});
            return;
        }
        self.mode_str = mkString(s, "kCFRunLoopDefaultMode");
        self.name_str = mkString(s, "fixnet.proxy.monitor");
        if (self.mode_str == null or self.name_str == null) {
            self.releaseObjects();
            std.log.warn("[proxy] mac monitor: mkString failed", .{});
            return;
        }

        var ctx = SCDynamicStoreContext{
            .version = 0,
            .info = self,
            .retain = null,
            .release = null,
            .copy_description = null,
        };
        self.store = s.sc_create(null, self.name_str.?, onProxyChange, &ctx);
        if (self.store == null) {
            self.releaseObjects();
            self.started.store(false, .release);
            std.log.warn("[proxy] mac monitor: SCDynamicStoreCreate failed", .{});
            return error.FailedToStartMonitor;
        }
        // 通知 keys：单个全局代理 key。
        const keys_val = [_]CFTypeRef{self.key_str.?};
        const keys_arr = s.cf_array_create(null, &keys_val, keys_val.len, null);
        if (keys_arr == null) {
            self.releaseObjects();
            self.started.store(false, .release);
            return error.FailedToStartMonitor;
        }
        const ok = s.sc_set_notif(self.store.?, keys_arr, null);
        s.cf_release(keys_arr);
        if (!ok) {
            self.releaseObjects();
            self.started.store(false, .release);
            std.log.warn("[proxy] mac monitor: SCDynamicStoreSetNotificationKeys failed", .{});
            return error.FailedToStartMonitor;
        }
        self.source = s.sc_mk_rls(null, self.store.?, 0);
        if (self.source == null) {
            self.releaseObjects();
            self.started.store(false, .release);
            return error.FailedToStartMonitor;
        }

        // 基线：先同步读一次当前值（不 emit），使 snapshot 立即可用。
        self.refresh(false);

        self.stop.store(false, .release);
        self.thread = std.Thread.spawn(.{}, runLoopThread, .{self}) catch {
            self.releaseObjects();
            self.started.store(false, .release);
            std.log.warn("[proxy] mac monitor: thread spawn failed", .{});
            return error.FailedToStartMonitor;
        };
        std.log.info("[proxy] mac monitor started (SCDynamicStore Global/Proxies)", .{});
    }

    pub fn subscribe(self: *Impl, cb: Callback, ctx: ?*anyopaque) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.sub_count >= MaxSubscribers) {
            std.log.warn("[proxy] subscriber registry full ({d}), subscribe ignored", .{MaxSubscribers});
            return error.TooManySubscribers;
        }
        self.subs[self.sub_count] = .{ .cb = cb, .ctx = ctx };
        self.sub_count += 1;
    }

    /// 当前系统代理快照；未 start / 从未成功读取时 null。
    pub fn snapshot(self: *Impl) ?ProxySettings {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.snapshot_ready) return null;
        return self.current;
    }

    /// 停止后台线程（幂等）：置 stop + CFRunLoopStop + join。
    pub fn close(self: *Impl) void {
        self.started.store(false, .release);
        if (self.thread) |t| {
            self.stop.store(true, .release);
            // 等待线程把 runloop ref 置位（最多 ~200ms），然后 stop 之。
            var waited: usize = 0;
            while (self.rl_ref.load(.acquire) == 0 and waited < 200) : (waited += 1) {
                zf.platform.sleepNs(1 * std.time.ns_per_ms);
            }
            const rl = self.rl_ref.load(.acquire);
            if (rl != 0) {
                if (self.sys) |s| s.cf_rl_stop(@ptrFromInt(rl));
            }
            t.join();
            self.thread = null;
            std.log.debug("[proxy] mac monitor stopped", .{});
        }
        self.releaseObjects();
    }

    pub fn deinit(self: *Impl) void {
        self.close();
        self.allocator.free(self.host_buf);
        self.host_buf = &.{};
    }

    // ---- 后台 CFRunLoop 线程 ----

    fn runLoopThread(self: *Impl) void {
        const s_val = self.sys orelse return;
        const s: *const Sys = &s_val;
        const rl = s.cf_rl_get_current();
        if (rl == null) return;
        self.rl_ref.store(@intFromPtr(rl), .release);
        s.cf_rl_add_source(rl, self.source.?, self.mode_str.?);
        s.cf_rl_run();
        s.cf_rl_remove_source(rl, self.source.?, self.mode_str.?);
        self.rl_ref.store(0, .release);
    }

    /// 重读当前代理 → diff →（可选）emit。在 CFRunLoop 线程/start 同步调用。
    fn refresh(self: *Impl, do_emit: bool) void {
        const s_val = self.sys orelse return;
        const s: *const Sys = &s_val;
        var host_local: [512]u8 = undefined;
        var fetched: ProxySettings = ProxySettings{};
        // SCDynamicStoreCopyProxies：读当前 effective proxies（NULL = 无代理配置 → disabled）。
        const dict = s.sc_copy_proxies(self.store.?);
        if (dict == null) {
            fetched = ProxySettings{};
        } else {
            defer release(s, dict);
            fetched = parseProxiesDict(s, dict, &host_local);
        }

        self.mutex.lock();
        const changed = !settingsEqual(self.current, fetched);
        if (changed) {
            if (self.host_buf.len > 0) {
                self.allocator.free(self.host_buf);
                self.host_buf = &.{};
            }
            if (fetched.host) |h| {
                self.host_buf = self.allocator.dupe(u8, h) catch {
                    std.log.warn("[proxy] mac: dup host failed, skip update", .{});
                    self.mutex.unlock();
                    return;
                };
            }
            self.current = ProxySettings{
                .enabled = fetched.enabled,
                .host = if (self.host_buf.len > 0) self.host_buf else null,
                .port = fetched.port,
            };
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

    /// 释放 CF 对象（close 或 start 中途失败后调用）。
    fn releaseObjects(self: *Impl) void {
        const s_val = self.sys orelse return;
        const s: *const Sys = &s_val;
        release(s, self.store);
        self.store = null;
        release(s, self.source);
        self.source = null;
        release(s, self.key_str);
        self.key_str = null;
        release(s, self.name_str);
        self.name_str = null;
        release(s, self.mode_str);
        self.mode_str = null;
    }
};

/// SCDynamicStore 变化 callout（CFRunLoop 线程触发）。
fn onProxyChange(store: CFTypeRef, changed_keys: CFTypeRef, info: ?*anyopaque) callconv(.c) void {
    _ = store;
    _ = changed_keys;
    const self: *Impl = @ptrCast(@alignCast(info orelse return));
    std.log.info("[proxy] mac: Global/Proxies changed", .{});
    self.refresh(true);
}

// ============================================================
// 单元测试（macOS 上运行：合成 CF 字典解析 + 生命周期 + 真值读取）
// ============================================================

const testing = std.testing;

fn requireSys() ?Sys {
    if (comptime !is_macos) return null;
    return loadSys();
}

/// 测试回调上下文（后台线程写、主线程读 → 锁保护）。
const TestCtx = struct {
    mutex: zf.sync.Mutex = .{},
    fired: bool = false,
};

fn onChange(settings: *const ProxySettings, ctx: ?*anyopaque) void {
    _ = settings;
    const c: *TestCtx = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    c.fired = true;
}

fn firedFlag(ctx: ?*anyopaque) bool {
    const c: *TestCtx = @ptrCast(@alignCast(ctx.?));
    c.mutex.lock();
    defer c.mutex.unlock();
    return c.fired;
}

fn waitUntil(pred: *const fn (?*anyopaque) bool, ctx: ?*anyopaque, timeout_ns: u64) bool {
    var waited: u64 = 0;
    while (waited < timeout_ns) : (waited += 10 * std.time.ns_per_ms) {
        if (pred(ctx)) return true;
        zf.platform.sleepNs(10 * std.time.ns_per_ms);
    }
    return pred(ctx);
}

test "proxy_monitor_darwin: lifecycle 启停幂等 + snapshot 一致性" {
    if (comptime !is_macos) return error.SkipZigTest;
    var mon = try Impl.init(testing.allocator);
    defer mon.deinit();

    // snapshot 未 start → null
    try testing.expect(mon.snapshot() == null);

    try mon.start();
    try mon.start(); // 幂等
    try testing.expect(mon.thread != null);

    // 基线已在 start 同步读 → snapshot 就绪；一致性：enabled ⇒ host != null
    if (mon.snapshot()) |s| {
        if (s.enabled) try testing.expect(s.host != null);
    }

    mon.close();
    mon.close(); // 幂等
    try testing.expect(mon.thread == null);

    // close 后可再 start（线程可复用）
    try mon.start();
    try testing.expect(mon.thread != null);
    mon.close();
    try testing.expect(mon.thread == null);
}

test "proxy_monitor_darwin: parseProxiesDict 禁用 + CFNumber 形态" {
    if (comptime !is_macos) return error.SkipZigTest;
    const s = requireSys().?;
    // 禁用：HTTPEnable = CFNumber(0)（实测系统无代理时即此形态）
    const disabled = s.cf_dict_create_mutable(null, 0, null, null).?;
    defer release(&s, disabled);
    var zero: i32 = 0;
    const nz = s.cf_number_create(null, kCFNumberSInt32Type, &zero).?;
    defer release(&s, nz);
    const en_k = mkString(&s, "HTTPEnable");
    defer release(&s, en_k);
    s.cf_dict_add_value(disabled, en_k, nz);

    var buf: [128]u8 = undefined;
    const r = parseProxiesDict(&s, disabled, &buf);
    try testing.expect(!r.enabled);
}

test "proxy_monitor_darwin: parseProxiesDict 启用（CFBoolean HTTP + CFNumber 端口）" {
    if (comptime !is_macos) return error.SkipZigTest;
    const s = requireSys().?;
    const dict = s.cf_dict_create_mutable(null, 0, null, null).?;
    defer release(&s, dict);

    const en_k = mkString(&s, "HTTPEnable");
    defer release(&s, en_k);
    s.cf_dict_add_value(dict, en_k, s.bool_true);

    const host_k = mkString(&s, "HTTPProxy");
    defer release(&s, host_k);
    const host_cf = mkString(&s, "127.0.0.1");
    defer release(&s, host_cf);
    s.cf_dict_add_value(dict, host_k, host_cf);

    const port_k = mkString(&s, "HTTPPort");
    defer release(&s, port_k);
    var port: i32 = 7890;
    const num = s.cf_number_create(null, kCFNumberSInt32Type, &port).?;
    defer release(&s, num);
    s.cf_dict_add_value(dict, port_k, num);

    var buf: [128]u8 = undefined;
    const r = parseProxiesDict(&s, dict, &buf);
    try testing.expect(r.enabled);
    try testing.expectEqualStrings("127.0.0.1", r.host.?);
    try testing.expectEqual(@as(u16, 7890), r.port);
}

test "proxy_monitor_darwin: settingsEqual 去重语义" {
    if (comptime !is_macos) return error.SkipZigTest;
    const a = ProxySettings{ .enabled = true, .host = "127.0.0.1", .port = 7890 };
    const b = ProxySettings{ .enabled = true, .host = "127.0.0.1", .port = 7890 };
    const c = ProxySettings{ .enabled = false, .host = null, .port = 0 };
    try testing.expect(settingsEqual(a, b));
    try testing.expect(!settingsEqual(a, c));
}

test "proxy_monitor_darwin: SCDynamicStoreCopyProxies 真值读取不崩溃" {
    // 端到端：建真实 store + copy proxies（不依赖事件），验证 API 链路与解析器
    // 对真实 proxies dict 的兼容性。环境异常（configd 不可用）→ 跳过。
    if (comptime !is_macos) return error.SkipZigTest;
    const s = requireSys().?;
    var ctx = SCDynamicStoreContext{ .version = 0, .info = null, .retain = null, .release = null, .copy_description = null };
    const name = mkString(&s, "zignetmon.test");
    defer release(&s, name);
    const store = s.sc_create(null, name, onProxyChange, &ctx) orelse return error.SkipZigTest;
    defer release(&s, store);

    const dict = s.sc_copy_proxies(store);
    if (dict == null) return; // 无代理配置：合法，仅跳过断言
    defer release(&s, dict);
    var buf: [512]u8 = undefined;
    const got = parseProxiesDict(&s, dict, &buf);
    if (got.enabled) try testing.expect(got.host != null);
}

// TODO(mac 真机事件验证)：
//  design.md §6 要求真事件经真实机器验证——本机自动化不修改系统代理，故事件触发
//  （System Settings 改代理 → callout 触发）留到 macvm 真机：改系统代理 →
//  确认 emit 且 snapshot 与系统一致、去掉代理 → disabled 且去重正确。
