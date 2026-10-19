//! The MCP tools: thin shapers over the DeGiro endpoints, returning TOON.
const std = @import("std");
const toon = @import("toon");
const degiro = @import("degiro.zig");
const dates = @import("dates.zig");
const url = @import("url.zig");
const sealed = @import("sealed.zig");

const Value = std.json.Value;
const log = std.log.scoped(.tools);

/// A check_order confirmation stays usable for this long. DeGiro expires its confirmationIds after a few
/// minutes as well; this keeps a stale check from being confirmed much later.
const confirmation_ttl = 10 * 60;
/// DeGiro's reporting endpoints refuse wider ranges.
const max_report_days = 366;
/// How far the default conversion limit sits from the live rate, so the order still fills when the
/// rate moves a little before it executes.
const fx_margin = 0.003;

pub const Result = struct {
    text: []const u8,
    is_error: bool = false,
};

/// A checked order, sealed into the confirmation_id handed to the client: DeGiro's confirmationId,
/// the exact order body that was checked, and its summary.
const OrderP = struct { c: []const u8, b: []const u8, s: []const u8, exp: i64 };

pub const Toolbox = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    dg: *degiro.Client,
    /// Order tools are only listed and callable when DEGIRO_TRADING is set.
    trading: bool,
    /// Enables the `_raw` and `_chart` passthroughs for local exploration.
    debug: bool = false,

    /// Seals confirmation_ids, so a checked order survives a restart without being stored.
    key: sealed.Key,

    mutex: std.Io.Mutex = .init,
    /// DeGiro confirmationIds already confirmed, until they expire: a confirmation_id places one
    /// order at most.
    used: std.StringHashMapUnmanaged(i64) = .empty,

    pub fn deinit(self: *Toolbox) void {
        var it = self.used.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.used.deinit(self.gpa);
    }

    pub fn listJson(self: *Toolbox) []const u8 {
        return if (self.trading) all_tools_json else read_tools_json;
    }

    pub fn call(self: *Toolbox, arena: std.mem.Allocator, name: []const u8, args: Value) !Result {
        var a: Args = .{ .v = args };
        var diag: []const u8 = "";
        const value = self.dispatch(arena, name, &a, &diag) catch |err| return switch (err) {
            error.OutOfMemory => err,
            error.LoginThrottled => .{ .is_error = true, .text = "DeGiro login is temporarily throttled after a recent attempt; try again in a few minutes." },
            error.LoginFailed => .{ .is_error = true, .text = "DeGiro login failed (check the server logs; credentials or TOTP may be wrong)." },
            error.UnknownTool => .{ .is_error = true, .text = try std.fmt.allocPrint(arena, "Unknown tool '{s}'", .{name}) },
            error.InvalidArgument => .{ .is_error = true, .text = a.problem },
            error.Upstream, error.Unauthorized => .{ .is_error = true, .text = try std.fmt.allocPrint(arena, "DeGiro rejected the request: {s}", .{
                if (diag.len > 0) upstreamMessage(arena, diag) else @errorName(err),
            }) },
            else => .{ .is_error = true, .text = try std.fmt.allocPrint(arena, "{s} failed: {t}", .{ name, err }) },
        };
        return .{ .text = try toon.encodeValueAlloc(arena, value, .{}) };
    }

    fn dispatch(self: *Toolbox, arena: std.mem.Allocator, name: []const u8, a: *Args, diag: *[]const u8) !Value {
        const eql = std.mem.eql;
        if (eql(u8, name, "get_portfolio")) return self.portfolio(arena, a);
        if (eql(u8, name, "get_open_orders")) return self.openOrders(arena);
        if (eql(u8, name, "get_order_history")) return self.report(arena, a, "v4/order-history", 90, diag);
        if (eql(u8, name, "get_transactions")) return self.report(arena, a, "v4/transactions", max_report_days, diag);
        if (eql(u8, name, "get_cash_movements")) return self.cashMovements(arena, a, diag);
        if (eql(u8, name, "search_products")) return self.search(arena, a, diag);
        if (eql(u8, name, "get_products")) return self.products(arena, a);
        if (eql(u8, name, "get_price_history")) return self.priceHistory(arena, a);
        if (self.trading) {
            if (eql(u8, name, "check_order")) return self.checkOrder(arena, a, diag);
            if (eql(u8, name, "check_conversion")) return self.checkConversion(arena, a, diag);
            if (eql(u8, name, "confirm_order")) return self.confirmOrder(arena, a, diag);
            if (eql(u8, name, "cancel_order")) return self.cancelOrder(arena, a, diag);
        }
        if (self.debug and eql(u8, name, "_raw")) {
            const base = std.meta.stringToEnum(degiro.Base, try a.str("base")) orelse return a.fail("bad base");
            return self.dg.call(arena, .{
                .base = base,
                .path = try a.str("path"),
                .query = a.optStr("query") orelse "",
                .method = if (a.optStr("body") != null) .POST else .GET,
                .body = a.optStr("body"),
                .jsessionid_path = base == .trading,
                .diag = diag,
            });
        }
        if (self.debug and eql(u8, name, "_chart")) return self.dg.chart(arena, try a.str("query"));
        return error.UnknownTool;
    }

    fn update(self: *Toolbox, arena: std.mem.Allocator, query: []const u8) !Value {
        return self.dg.call(arena, .{ .base = .trading, .path = "v5/update/{intAccount}", .query = query, .jsessionid_path = true });
    }

    fn portfolio(self: *Toolbox, arena: std.mem.Allocator, a: *Args) !Value {
        const include_closed = a.optBool("include_closed") orelse false;
        const res = try self.update(arena, "portfolio=0&totalPortfolio=0");
        const rows = try flattenRows(arena, field(res, "portfolio"));

        var ids: std.ArrayList([]const u8) = .empty;
        for (rows) |r| if (isProduct(r) and (include_closed or num(r.get("size")) != 0)) try ids.append(arena, idString(arena, r.get("id")));
        const info = try self.productInfo(arena, ids.items);

        var positions: Array = .init(arena);
        var cash: Array = .init(arena);
        for (rows) |r| {
            if (!isProduct(r)) {
                if (num(r.get("size")) == 0) continue;
                var c: Obj = .init(arena);
                try c.put("currency", r.get("id") orelse .null);
                try c.put("amount", r.get("size") orelse .null);
                try c.put("value_eur", r.get("value") orelse .null);
                try cash.append(c.value());
                continue;
            }
            const size = num(r.get("size"));
            if (!include_closed and size == 0) continue;
            const id = idString(arena, r.get("id"));
            const p = info.get(id) orelse Value.null;
            const price = num(r.get("price"));
            const bep = num(r.get("breakEvenPrice"));

            var o: Obj = .init(arena);
            try o.put("product_id", .{ .string = id });
            try o.put("name", field(p, "name"));
            try o.put("symbol", field(p, "symbol"));
            try o.put("isin", field(p, "isin"));
            try o.put("currency", field(p, "currency"));
            try o.put("size", r.get("size") orelse .null);
            try o.put("price", r.get("price") orelse .null);
            try o.put("break_even_price", r.get("breakEvenPrice") orelse .null);
            try o.put("value_eur", r.get("value") orelse .null);
            try o.put("unrealized_pct", if (bep != 0 and size != 0) .{ .float = round2((price / bep - 1) * 100) } else .null);
            // DeGiro's plBase/todayPlBase are minus the cost basis (overall / at today's open) in EUR,
            // so P/L is value plus that.
            const value_eur = num(r.get("value"));
            try o.put("cost_basis_eur", .{ .float = round2(-num(eurOf(r.get("plBase")))) });
            try o.put("total_pl_eur", .{ .float = round2(value_eur + num(eurOf(r.get("plBase")))) });
            try o.put("today_pl_eur", .{ .float = round2(value_eur + num(eurOf(r.get("todayPlBase")))) });
            try positions.append(o.value());
        }

        const totals = try flattenFlat(arena, field(res, "totalPortfolio"));
        var t: Obj = .init(arena);
        try t.put("total_cash_eur", totals.get("totalCash") orelse .null);
        try t.put("free_space", totals.get("freeSpaceNew") orelse .null);
        try t.put("total_deposits_eur", totals.get("totalDepositWithdrawal") orelse .null);
        try t.put("total_non_product_fees_eur", totals.get("totalNonProductFees") orelse .null);
        try t.put("pending_settlement_eur", totals.get("pendingSettlement") orelse .null);

        var out: Obj = .init(arena);
        try out.put("totals", t.value());
        try out.put("positions", .{ .array = positions });
        try out.put("cash", .{ .array = cash });
        return out.value();
    }

    fn openOrders(self: *Toolbox, arena: std.mem.Allocator) !Value {
        const res = try self.update(arena, "orders=0");
        const rows = try flattenRows(arena, field(res, "orders"));
        var ids: std.ArrayList([]const u8) = .empty;
        for (rows) |r| if (r.get("productId")) |pid| try ids.append(arena, idString(arena, pid));
        const info = try self.productNames(arena, ids.items);

        var out: Array = .init(arena);
        for (rows) |r| {
            var o: Obj = .init(arena);
            const pid = idString(arena, r.get("productId"));
            try o.put("order_id", r.get("id") orelse .null);
            try o.put("product_id", .{ .string = pid });
            try o.put("name", field(info.get(pid) orelse .null, "name"));
            try o.put("side", r.get("buysell") orelse .null);
            try o.put("order_type", orderTypeName(r.get("orderTypeId")));
            try o.put("time_type", timeTypeName(r.get("orderTimeTypeId")));
            try o.put("size", r.get("size") orelse .null);
            try o.put("price", r.get("price") orelse .null);
            try o.put("stop_price", r.get("stopPrice") orelse .null);
            try o.put("currency", r.get("currency") orelse .null);
            try o.put("created", r.get("date") orelse .null);
            try o.put("modifiable", r.get("isModifiable") orelse .null);
            try out.append(o.value());
        }
        var res_obj: Obj = .init(arena);
        try res_obj.put("open_orders", .{ .array = out });
        return res_obj.value();
    }

    /// order-history and transactions: same date-range query, rows with a productId to resolve.
    fn report(self: *Toolbox, arena: std.mem.Allocator, a: *Args, path: []const u8, max_days: i64, diag: *[]const u8) !Value {
        const range = try self.dateRange(arena, a, max_days);
        const query = try std.fmt.allocPrint(arena, "fromDate={s}&toDate={s}&groupTransactionsByOrder=false", .{ range.from, range.to });
        const res = try self.dg.call(arena, .{ .base = .reporting, .path = path, .query = query, .diag = diag });
        const data = field(res, "data");
        if (data != .array) return res;

        var ids: std.ArrayList([]const u8) = .empty;
        for (data.array.items) |r| if (r == .object) if (r.object.get("productId")) |pid| try ids.append(arena, idString(arena, pid));
        const info = try self.productNames(arena, ids.items);

        // Keep the rows as DeGiro sends them, minus regulatory noise, plus the product name.
        const drop = [_][]const u8{ "executingEntityId", "transfered", "counterParty", "nettFxRate", "grossFxRate", "transactionTypeId" };
        for (data.array.items) |*r| {
            if (r.* != .object) continue;
            for (drop) |k| _ = r.object.orderedRemove(k);
            const pid = idString(arena, r.object.get("productId"));
            try r.object.put(arena, "name", field(info.get(pid) orelse .null, "name"));
            if (r.object.get("orderTypeId")) |t| try r.object.put(arena, "orderTypeId", orderTypeName(t));
            if (r.object.get("orderTimeTypeId")) |t| try r.object.put(arena, "orderTimeTypeId", timeTypeName(t));
        }
        var out: Obj = .init(arena);
        try out.put("from", .{ .string = range.from_iso });
        try out.put("to", .{ .string = range.to_iso });
        try out.put("rows", data);
        return out.value();
    }

    fn cashMovements(self: *Toolbox, arena: std.mem.Allocator, a: *Args, diag: *[]const u8) !Value {
        const range = try self.dateRange(arena, a, max_report_days);
        const query = try std.fmt.allocPrint(arena, "fromDate={s}&toDate={s}", .{ range.from, range.to });
        const res = try self.dg.call(arena, .{ .base = .reporting, .path = "v6/accountoverview", .query = query, .diag = diag });
        const moves = field(field(res, "data"), "cashMovements");
        var out: Array = .init(arena);
        if (moves == .array) for (moves.array.items) |m| {
            var o: Obj = .init(arena);
            try o.put("date", field(m, "date"));
            try o.put("type", field(m, "type"));
            try o.put("description", field(m, "description"));
            try o.put("currency", field(m, "currency"));
            try o.put("change", field(m, "change"));
            try o.put("balance_total", field(field(m, "balance"), "total"));
            try o.put("product_id", field(m, "productId"));
            try out.append(o.value());
        };
        var res_obj: Obj = .init(arena);
        try res_obj.put("from", .{ .string = range.from_iso });
        try res_obj.put("to", .{ .string = range.to_iso });
        try res_obj.put("cash_movements", .{ .array = out });
        return res_obj.value();
    }

    fn search(self: *Toolbox, arena: std.mem.Allocator, a: *Args, diag: *[]const u8) !Value {
        const q = try a.str("query");
        const limit = std.math.clamp(a.optInt("limit") orelse 10, 1, 50);
        var type_param: []const u8 = "";
        if (a.optStr("type")) |t| {
            const id = productTypeId(t) orelse return a.fail("type must be one of: stock, etf, bond, fund, option, future, leveraged, warrant, cfd");
            type_param = try std.fmt.allocPrint(arena, "&productTypeId={d}", .{id});
        }
        const query = try std.fmt.allocPrint(arena, "searchText={f}&limit={d}&offset=0{s}", .{ url.encoded(q), limit, type_param });
        const res = try self.dg.call(arena, .{ .base = .product_search, .path = "v5/products/lookup", .query = query, .diag = diag });
        var out: Array = .init(arena);
        const found = field(res, "products");
        if (found == .array) for (found.array.items) |p| try out.append(try summarizeProduct(arena, p, false));
        var res_obj: Obj = .init(arena);
        try res_obj.put("products", .{ .array = out });
        return res_obj.value();
    }

    fn products(self: *Toolbox, arena: std.mem.Allocator, a: *Args) !Value {
        const ids = try a.idList(arena, "product_ids");
        const info = try self.productInfo(arena, ids);
        var out: Array = .init(arena);
        for (ids) |id| if (info.get(id)) |p| try out.append(try summarizeProduct(arena, p, true));
        var res_obj: Obj = .init(arena);
        try res_obj.put("products", .{ .array = out });
        return res_obj.value();
    }

    fn priceHistory(self: *Toolbox, arena: std.mem.Allocator, a: *Args) !Value {
        const id = try a.id(arena, "product_id");
        const period = a.optStr("period") orelse "P1M";
        if (!validPeriod(period)) return a.fail("period must be an ISO 8601 duration such as P1D, P1W, P1M, P3M, P6M, P1Y, P5Y or YTD");
        const resolution = a.optStr("resolution") orelse defaultResolution(period);
        if (!validPeriod(resolution)) return a.fail("resolution must be an ISO 8601 duration such as PT1M, PT15M, PT1H, P1D, P1W or P1M");

        const info = try self.productInfo(arena, &.{id});
        const p = info.get(id) orelse return a.fail("unknown product_id");
        const series = try vwdSeries(arena, p) orelse return a.fail("no price feed for this product");
        const ohlc = try std.fmt.allocPrint(arena, "ohlc:{s}", .{series});

        const query = try std.fmt.allocPrint(arena, "resolution={s}&period={s}&series={f}&series={f}", .{ resolution, period, url.encoded(series), url.encoded(ohlc) });
        const res = try self.dg.chart(arena, query);

        var out: Obj = .init(arena);
        try out.put("product_id", .{ .string = id });
        try out.put("name", field(p, "name"));
        try out.put("currency", field(p, "currency"));
        try out.put("period", .{ .string = period });
        try out.put("resolution", .{ .string = resolution });
        const all = field(res, "series");
        if (all == .array) for (all.array.items) |s| {
            const kind = field(s, "type");
            if (kind != .string) continue;
            if (std.mem.eql(u8, kind.string, "object")) {
                const q = field(s, "data");
                var quote: Obj = .init(arena);
                inline for (.{ "lastPrice", "lastTime", "absDiff", "relDiff", "openPrice", "highPrice", "lowPrice", "previousClosePrice", "cumulativeVolume", "lowPriceP1Y", "highPriceP1Y", "market", "quality" }) |k|
                    try quote.put(k, field(q, k));
                try out.put("quote", quote.value());
            } else if (std.mem.eql(u8, kind.string, "ohlc")) {
                try out.put("candles", try candles(arena, s));
            }
        };
        return out.value();
    }

    fn checkOrder(self: *Toolbox, arena: std.mem.Allocator, a: *Args, diag: *[]const u8) !Value {
        const id = try a.id(arena, "product_id");
        const side_s = try a.str("side");
        const side: []const u8 = if (std.ascii.eqlIgnoreCase(side_s, "buy")) "BUY" else if (std.ascii.eqlIgnoreCase(side_s, "sell")) "SELL" else return a.fail("side must be BUY or SELL");
        const order_type = orderTypeId(try a.str("order_type")) orelse return a.fail("order_type must be LIMIT, MARKET, STOPLOSS or STOPLIMIT");
        const time_s = a.optStr("time_type") orelse "DAY";
        const time_type: i64 = if (std.ascii.eqlIgnoreCase(time_s, "day")) 1 else if (std.ascii.eqlIgnoreCase(time_s, "gtc")) 3 else return a.fail("time_type must be DAY or GTC");
        const size = a.optNum("size") orelse return a.fail("size is required");
        if (size <= 0) return a.fail("size must be positive");
        const price = a.optNum("price");
        const stop = a.optNum("stop_price");
        const needs_price = order_type == 0 or order_type == 1;
        const needs_stop = order_type == 1 or order_type == 3;
        if (needs_price and price == null) return a.fail("price is required for LIMIT and STOPLIMIT orders");
        if (needs_stop and stop == null) return a.fail("stop_price is required for STOPLOSS and STOPLIMIT orders");

        // DeGiro only accepts the fields that belong to the order type.
        var body: Obj = .init(arena);
        try body.put("buySell", .{ .string = side });
        try body.put("orderType", .{ .integer = order_type });
        try body.put("productId", .{ .string = id });
        try body.put("size", .{ .float = size });
        try body.put("timeType", .{ .integer = time_type });
        if (needs_price) try body.put("price", .{ .float = price.? });
        if (needs_stop) try body.put("stopPrice", .{ .float = stop.? });
        const body_json = try std.json.Stringify.valueAlloc(arena, body.value(), .{});

        const res = try self.dg.call(arena, .{
            .method = .POST,
            .base = .trading,
            .path = "v5/checkOrder",
            .body = body_json,
            .jsessionid_path = true,
            .diag = diag,
        });
        const data = field(res, "data");
        const confirmation = field(data, "confirmationId");
        if (confirmation != .string) return res;

        const info = try self.productInfo(arena, &.{id});
        const p = info.get(id) orelse Value.null;
        const name = field(p, "name");
        const isin = field(p, "isin");
        const summary = try std.fmt.allocPrint(arena, "{s} {d} x {s} ({s}) {s}{s}{s} {s}", .{
            side,
            size,
            if (name == .string) name.string else id,
            if (isin == .string) isin.string else "?",
            orderTypeName(.{ .integer = order_type }).string,
            if (price) |v| try std.fmt.allocPrint(arena, " @ {d}", .{v}) else "",
            if (stop) |v| try std.fmt.allocPrint(arena, " stop {d}", .{v}) else "",
            if (time_type == 3) "GTC" else "DAY",
        });
        const token = try sealed.seal(arena, self.io, self.key, .order, OrderP{
            .c = confirmation.string,
            .b = body_json,
            .s = summary,
            .exp = sealed.now(self.io) + confirmation_ttl,
        });

        var out: Obj = .init(arena);
        try out.put("confirmation_id", .{ .string = token });
        try out.put("order", .{ .string = summary });
        try out.put("currency", field(p, "currency"));
        try out.put("transaction_fee", field(data, "transactionFee"));
        try out.put("fees", field(data, "transactionFees"));
        try out.put("opposite_fees", field(data, "transactionOppositeFees"));
        try out.put("taxes", field(data, "transactionTaxes"));
        try out.put("auto_fx_surcharges", field(data, "transactionAutoFxSurcharges"));
        try out.put("auto_fx_rate", field(data, "autoFxConversionRate"));
        try out.put("free_space_after", field(data, "freeSpaceNew"));
        try out.put("next_step", .{ .string = "Show this to the user. Only after they explicitly approve, call confirm_order with this confirmation_id (valid for 10 minutes)." });
        return out.value();
    }

    /// Currency exchange as an order on DeGiro's EUR/XXX product. DeGiro sizes those in whole euros
    /// at a rate in XXX per euro; this works the size out from the amount, so converting a whole
    /// balance can't overshoot it.
    fn checkConversion(self: *Toolbox, arena: std.mem.Allocator, a: *Args, diag: *[]const u8) !Value {
        const from = try currencyCode(arena, a, "from");
        const to = try currencyCode(arena, a, "to");
        if (std.mem.eql(u8, from, to)) return a.fail("from and to must differ");
        const to_eur = std.mem.eql(u8, to, "EUR");
        if (!to_eur and !std.mem.eql(u8, from, "EUR")) return a.fail("DeGiro only exchanges to or from EUR; convert in two steps");
        const foreign = if (to_eur) from else to;

        const all = a.optBool("all") orelse false;
        const amount_arg = a.optNum("amount");
        if (all == (amount_arg != null)) return a.fail("give either amount or all=true");
        // The transaction fee is charged in EUR, so "all" of the EUR balance would overdraw it.
        if (all and !to_eur) return a.fail("all=true only converts a foreign balance to EUR; give an amount in EUR instead");

        const product = try self.fxProduct(arena, foreign, diag) orelse
            return a.fail(try std.fmt.allocPrint(arena, "DeGiro has no EUR/{s} currency product", .{foreign}));
        const id = idString(arena, field(product, "id"));
        const live = try self.livePrice(arena, product);

        // Buying EUR, the limit is the most XXX paid per euro; selling EUR, the least received.
        const rate = if (a.optNum("rate")) |r| r else blk: {
            const l = live orelse return a.fail("no live rate available; pass rate explicitly");
            break :blk if (to_eur) l * (1 + fx_margin) else l * (1 - fx_margin);
        };
        if (!(rate > 0)) return a.fail("rate must be positive");
        const limit = fxLimit(to_eur, rate);

        const amount = amount_arg orelse try self.freeCash(arena, from);
        if (!(amount > 0)) return a.fail(try std.fmt.allocPrint(arena, "nothing to convert: free {s} is {d}", .{ from, amount }));
        const size = fxSize(to_eur, amount, limit);
        if (size < 1) return a.fail("amount is less than one euro at this rate");

        var order: std.json.ObjectMap = .empty;
        try order.put(arena, "product_id", .{ .string = id });
        try order.put(arena, "side", .{ .string = if (to_eur) "BUY" else "SELL" });
        try order.put(arena, "order_type", .{ .string = "LIMIT" });
        try order.put(arena, "size", .{ .float = size });
        try order.put(arena, "price", .{ .float = limit });
        var sub: Args = .{ .v = .{ .object = order } };
        var out = self.checkOrder(arena, &sub, diag) catch |err| {
            if (err == error.InvalidArgument) a.problem = sub.problem;
            return err;
        };
        if (out != .object or out.object.get("confirmation_id") == null) return out;

        const foreign_amount = size * limit;
        try out.object.put(arena, "from", .{ .string = from });
        try out.object.put(arena, "to", .{ .string = to });
        try out.object.put(arena, "live_rate", if (live) |l| .{ .float = l } else .null);
        try out.object.put(arena, "limit_rate", .{ .float = limit });
        if (to_eur) {
            try out.object.put(arena, "receive_eur", .{ .float = size });
            try out.object.put(arena, "pay_at_most", .{ .float = round2(foreign_amount) });
            try out.object.put(arena, "left_over_at_most", .{ .float = round2(amount - foreign_amount) });
        } else {
            try out.object.put(arena, "pay_eur", .{ .float = size });
            try out.object.put(arena, "receive_at_least", .{ .float = round2(foreign_amount) });
        }
        return out;
    }

    /// The EUR/XXX currency product, found by its exact symbol.
    fn fxProduct(self: *Toolbox, arena: std.mem.Allocator, foreign: []const u8, diag: *[]const u8) !?Value {
        const symbol = try std.fmt.allocPrint(arena, "EUR/{s}", .{foreign});
        const query = try std.fmt.allocPrint(arena, "searchText={f}&limit=10&offset=0", .{url.encoded(symbol)});
        const res = try self.dg.call(arena, .{ .base = .product_search, .path = "v5/products/lookup", .query = query, .diag = diag });
        const found = field(res, "products");
        if (found == .array) for (found.array.items) |p| {
            const sym = field(p, "symbol");
            const kind = field(p, "productType");
            if (sym == .string and kind == .string and std.mem.eql(u8, sym.string, symbol) and std.mem.eql(u8, kind.string, "CURRENCY")) return p;
        };
        return null;
    }

    /// Last traded price from vwd, or null when the product has no feed.
    fn livePrice(self: *Toolbox, arena: std.mem.Allocator, p: Value) !?f64 {
        const series = try vwdSeries(arena, p) orelse return null;
        const query = try std.fmt.allocPrint(arena, "resolution=PT1H&period=P1D&series={f}", .{url.encoded(series)});
        const res = try self.dg.chart(arena, query);
        const all = field(res, "series");
        if (all == .array) for (all.array.items) |s| {
            const last = field(field(s, "data"), "lastPrice");
            if (last == .float or last == .integer) return num(last);
        };
        return null;
    }

    /// Free cash in one currency, as DeGiro's free space shows it.
    fn freeCash(self: *Toolbox, arena: std.mem.Allocator, currency: []const u8) !f64 {
        const res = try self.update(arena, "totalPortfolio=0");
        const totals = try flattenFlat(arena, field(res, "totalPortfolio"));
        return num(field(totals.get("freeSpaceNew") orelse .null, currency));
    }

    fn confirmOrder(self: *Toolbox, arena: std.mem.Allocator, a: *Args, diag: *[]const u8) !Value {
        const cid = try a.str("confirmation_id");
        const order = sealed.open(OrderP, arena, self.io, self.key, .order, cid) orelse
            return a.fail("Unknown or expired confirmation_id. Run check_order again and get the user's approval for the new quote.");
        if (std.mem.indexOfAny(u8, order.c, "/;?&#% ") != null) return a.fail("invalid confirmation_id");
        if (!try self.markUsed(order.c, order.exp))
            return a.fail("This confirmation_id was already used. Run check_order again for a new order.");

        const path = try std.fmt.allocPrint(arena, "v5/order/{s}", .{order.c});
        const res = try self.dg.call(arena, .{
            .method = .POST,
            .base = .trading,
            .path = path,
            .body = order.b,
            .jsessionid_path = true,
            .diag = diag,
        });
        log.warn("order placed", .{});
        var out: Obj = .init(arena);
        try out.put("placed", .{ .bool = true });
        try out.put("order", .{ .string = order.s });
        try out.put("order_id", field(field(res, "data"), "orderId"));
        return out.value();
    }

    fn cancelOrder(self: *Toolbox, arena: std.mem.Allocator, a: *Args, diag: *[]const u8) !Value {
        const oid = try a.str("order_id");
        if (oid.len == 0 or std.mem.indexOfAny(u8, oid, "/;?&#% ") != null) return a.fail("invalid order_id");
        const path = try std.fmt.allocPrint(arena, "v5/order/{s}", .{oid});
        _ = try self.dg.call(arena, .{ .method = .DELETE, .base = .trading, .path = path, .jsessionid_path = true, .diag = diag });
        log.warn("order cancelled", .{});
        var out: Obj = .init(arena);
        try out.put("cancelled", .{ .bool = true });
        try out.put("order_id", .{ .string = oid });
        return out.value();
    }

    /// Records a confirmation as used; false if it already was. Expired entries are dropped first,
    /// so the set stays as small as the number of orders placed in the last few minutes.
    fn markUsed(self: *Toolbox, confirmation: []const u8, exp: i64) !bool {
        try self.mutex.lock(self.io);
        defer self.mutex.unlock(self.io);
        const now = sealed.now(self.io);
        var it = self.used.iterator();
        while (it.next()) |e| if (e.value_ptr.* < now) {
            const k = e.key_ptr.*;
            self.used.removeByPtr(e.key_ptr);
            self.gpa.free(k);
            it = self.used.iterator();
        };
        if (self.used.contains(confirmation)) return false;
        const k = try self.gpa.dupe(u8, confirmation);
        errdefer self.gpa.free(k);
        try self.used.put(self.gpa, k, exp);
        return true;
    }

    /// Product info only used to decorate rows with names: a failure leaves the names out rather than
    /// failing the whole tool.
    fn productNames(self: *Toolbox, arena: std.mem.Allocator, ids: []const []const u8) !std.StringHashMapUnmanaged(Value) {
        return self.productInfo(arena, ids) catch |err| switch (err) {
            error.OutOfMemory => err,
            else => blk: {
                log.warn("product info lookup failed ({t}); returning rows without names", .{err});
                break :blk .empty;
            },
        };
    }

    /// Product info keyed by id string. Unknown ids are simply missing.
    fn productInfo(self: *Toolbox, arena: std.mem.Allocator, ids: []const []const u8) !std.StringHashMapUnmanaged(Value) {
        var map: std.StringHashMapUnmanaged(Value) = .empty;
        // The endpoint answers 500 on duplicate ids.
        var unique: std.ArrayList([]const u8) = .empty;
        var seen: std.StringHashMapUnmanaged(void) = .empty;
        for (ids) |id| if (id.len > 0 and !(try seen.getOrPut(arena, id)).found_existing) try unique.append(arena, id);
        if (unique.items.len == 0) return map;
        const body = try std.json.Stringify.valueAlloc(arena, unique.items, .{});
        const res = try self.dg.call(arena, .{ .method = .POST, .base = .product_search, .path = "v5/products/info", .body = body });
        const data = field(res, "data");
        if (data == .object) {
            var it = data.object.iterator();
            while (it.next()) |e| try map.put(arena, e.key_ptr.*, e.value_ptr.*);
        }
        return map;
    }

    const Range = struct { from: []const u8, to: []const u8, from_iso: []const u8, to_iso: []const u8 };

    fn dateRange(self: *Toolbox, arena: std.mem.Allocator, a: *Args, max_days: i64) !Range {
        const today = @divFloor(std.Io.Timestamp.now(self.io, .real).toSeconds(), 86400) * 86400;
        const to = if (a.optStr("to")) |s| dates.parse(s) orelse return a.fail("to must be YYYY-MM-DD") else today;
        const from = if (a.optStr("from")) |s| dates.parse(s) orelse return a.fail("from must be YYYY-MM-DD") else to - 30 * 86400;
        if (from > to) return a.fail("from is after to");
        if (to - from > max_days * 86400) return a.fail(try std.fmt.allocPrint(arena, "range too wide: DeGiro allows at most {d} days here", .{max_days}));
        var b: [4][10]u8 = undefined;
        return .{
            .from = try arena.dupe(u8, dates.degiroDate(&b[0], from)),
            .to = try arena.dupe(u8, dates.degiroDate(&b[1], to)),
            .from_iso = try arena.dupe(u8, dates.isoDate(&b[2], from)),
            .to_iso = try arena.dupe(u8, dates.isoDate(&b[3], to)),
        };
    }
};

const Array = std.json.Array;

const Obj = struct {
    arena: std.mem.Allocator,
    map: std.json.ObjectMap = .empty,

    fn init(arena: std.mem.Allocator) Obj {
        return .{ .arena = arena };
    }

    fn put(o: *Obj, key: []const u8, v: Value) !void {
        try o.map.put(o.arena, key, v);
    }

    fn value(o: Obj) Value {
        return .{ .object = o.map };
    }
};

/// Typed access to a tool's `arguments` object. `problem` holds the message for error.InvalidArgument.
const Args = struct {
    v: Value,
    problem: []const u8 = "",

    fn get(a: *Args, key: []const u8) ?Value {
        if (a.v != .object) return null;
        const x = a.v.object.get(key) orelse return null;
        return if (x == .null) null else x;
    }

    fn fail(a: *Args, msg: []const u8) error{InvalidArgument} {
        a.problem = msg;
        return error.InvalidArgument;
    }

    fn optStr(a: *Args, key: []const u8) ?[]const u8 {
        const x = a.get(key) orelse return null;
        return if (x == .string) x.string else null;
    }

    fn str(a: *Args, key: []const u8) ![]const u8 {
        return a.optStr(key) orelse a.fail(key);
    }

    fn optBool(a: *Args, key: []const u8) ?bool {
        const x = a.get(key) orelse return null;
        return if (x == .bool) x.bool else null;
    }

    fn optInt(a: *Args, key: []const u8) ?i64 {
        const x = a.get(key) orelse return null;
        return switch (x) {
            .integer => |i| i,
            .float => |f| @intFromFloat(f),
            .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
            else => null,
        };
    }

    fn optNum(a: *Args, key: []const u8) ?f64 {
        const x = a.get(key) orelse return null;
        return switch (x) {
            .integer => |i| @floatFromInt(i),
            .float => |f| f,
            .string, .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
            else => null,
        };
    }

    /// A DeGiro product id, accepted as number or numeric string.
    fn id(a: *Args, arena: std.mem.Allocator, key: []const u8) ![]const u8 {
        const x = a.get(key) orelse return a.fail(try std.fmt.allocPrint(arena, "{s} is required", .{key}));
        return parseId(arena, x) orelse a.fail(try std.fmt.allocPrint(arena, "{s} must be a numeric DeGiro product id", .{key}));
    }

    fn idList(a: *Args, arena: std.mem.Allocator, key: []const u8) ![]const []const u8 {
        const x = a.get(key) orelse return a.fail(try std.fmt.allocPrint(arena, "{s} is required", .{key}));
        if (x != .array or x.array.items.len == 0 or x.array.items.len > 50) return a.fail(try std.fmt.allocPrint(arena, "{s} must be a list of 1-50 product ids", .{key}));
        const out = try arena.alloc([]const u8, x.array.items.len);
        for (x.array.items, out) |item, *o| o.* = parseId(arena, item) orelse return a.fail("product ids must be numeric");
        return out;
    }
};

/// DeGiro takes FX rates to 4 decimals; rounding goes against us so the limit stays a bound.
fn fxLimit(buying_eur: bool, rate: f64) f64 {
    return if (buying_eur) @ceil(rate * 10_000) / 10_000 else @floor(rate * 10_000) / 10_000;
}

/// Whole euros to buy with `amount` of the foreign currency at most `limit` each, or to sell out of
/// `amount` euros.
fn fxSize(buying_eur: bool, amount: f64, limit: f64) f64 {
    return if (buying_eur) @floor(amount / limit) else @floor(amount);
}

fn currencyCode(arena: std.mem.Allocator, a: *Args, key: []const u8) ![]const u8 {
    const v = try a.str(key);
    if (v.len != 3) return a.fail(try std.fmt.allocPrint(arena, "{s} must be a 3-letter currency code", .{key}));
    const out = try arena.alloc(u8, 3);
    for (v, out) |c, *o| {
        if (!std.ascii.isAlphabetic(c)) return a.fail(try std.fmt.allocPrint(arena, "{s} must be a 3-letter currency code", .{key}));
        o.* = std.ascii.toUpper(c);
    }
    return out;
}

fn parseId(arena: std.mem.Allocator, x: Value) ?[]const u8 {
    switch (x) {
        .integer => |i| return std.fmt.allocPrint(arena, "{d}", .{i}) catch null,
        .string => |s| {
            if (s.len == 0 or s.len > 20) return null;
            for (s) |c| if (!std.ascii.isDigit(c)) return null;
            return s;
        },
        else => return null,
    }
}

fn field(v: Value, key: []const u8) Value {
    if (v != .object) return .null;
    return v.object.get(key) orelse .null;
}

fn num(v: ?Value) f64 {
    const x = v orelse return 0;
    return switch (x) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string, .string => |s| std.fmt.parseFloat(f64, s) catch 0,
        else => 0,
    };
}

fn round2(x: f64) f64 {
    return @round(x * 100) / 100;
}

fn idString(arena: std.mem.Allocator, v: ?Value) []const u8 {
    const x = v orelse return "";
    return switch (x) {
        .string => |s| s,
        .integer => |i| std.fmt.allocPrint(arena, "{d}", .{i}) catch "",
        else => "",
    };
}

fn eurOf(v: ?Value) ?Value {
    const x = v orelse return null;
    if (x != .object) return x;
    return x.object.get("EUR");
}

fn isProduct(row: std.json.ObjectMap) bool {
    const t = row.get("positionType") orelse return false;
    return t == .string and std.mem.eql(u8, t.string, "PRODUCT");
}

/// The update endpoint wraps every row as {name, id, value: [{name, value}, ...]}; flatten each row's
/// fields into one map.
fn flattenRows(arena: std.mem.Allocator, section: Value) ![]std.json.ObjectMap {
    const rows = field(section, "value");
    if (rows != .array) return &.{};
    var out: std.ArrayList(std.json.ObjectMap) = .empty;
    for (rows.array.items) |row| try out.append(arena, try flattenFlat(arena, row));
    return out.items;
}

fn flattenFlat(arena: std.mem.Allocator, row: Value) !std.json.ObjectMap {
    var m: std.json.ObjectMap = .empty;
    const fields = field(row, "value");
    if (fields != .array) return m;
    for (fields.array.items) |f| {
        const n = field(f, "name");
        if (n != .string) continue;
        try m.put(arena, n.string, field(f, "value"));
    }
    return m;
}

fn summarizeProduct(arena: std.mem.Allocator, p: Value, detailed: bool) !Value {
    var o: Obj = .init(arena);
    try o.put("product_id", field(p, "id"));
    try o.put("name", field(p, "name"));
    try o.put("symbol", field(p, "symbol"));
    try o.put("isin", field(p, "isin"));
    try o.put("type", field(p, "productType"));
    try o.put("currency", field(p, "currency"));
    try o.put("exchange_id", field(p, "exchangeId"));
    try o.put("close_price", field(p, "closePrice"));
    try o.put("close_date", field(p, "closePriceDate"));
    try o.put("tradable", field(p, "tradable"));
    if (detailed) {
        try o.put("contract_size", field(p, "contractSize"));
        try o.put("buy_order_types", field(p, "buyOrderTypes"));
        try o.put("sell_order_types", field(p, "sellOrderTypes"));
        try o.put("time_types", field(p, "orderTimeTypes"));
        try o.put("shortable", field(p, "isShortable"));
        try o.put("feed_quality", field(p, "feedQuality"));
    }
    return o.value();
}

/// vwd series identifier for a product, e.g. "issueid:16923" or "vwdkey:MRVL.BATS,E". Falls back to
/// the secondary feed when the primary one has no id.
fn vwdSeries(arena: std.mem.Allocator, p: Value) !?[]const u8 {
    inline for (.{ .{ "vwdIdentifierType", "vwdId" }, .{ "vwdIdentifierTypeSecondary", "vwdIdSecondary" } }) |keys| {
        const t = field(p, keys[0]);
        const id = field(p, keys[1]);
        if (t == .string and id == .string and id.string.len > 0)
            return try std.fmt.allocPrint(arena, "{s}:{s}", .{ t.string, id.string });
    }
    return null;
}

/// Turns vwd's {times: "<start>/<step>", data: [[i, o, h, l, c], ...]} into dated candle rows.
fn candles(arena: std.mem.Allocator, s: Value) !Value {
    const times = field(s, "times");
    const data = field(s, "data");
    var out: Array = .init(arena);
    if (times != .string or data != .array) return .{ .array = out };
    const slash = std.mem.indexOfScalar(u8, times.string, '/') orelse return .{ .array = out };
    const start = dates.parse(times.string[0..slash]);
    const step = dates.durationSeconds(times.string[slash + 1 ..]);

    for (data.array.items) |row| {
        if (row != .array or row.array.items.len < 5) continue;
        const r = row.array.items;
        var o: Obj = .init(arena);
        if (start != null and step != null) {
            const t = start.? + @as(i64, @intFromFloat(num(r[0]) * @as(f64, @floatFromInt(step.?))));
            try o.put("time", .{ .string = try dates.formatAlloc(arena, t) });
        } else {
            try o.put("index", r[0]);
        }
        try o.put("open", r[1]);
        try o.put("high", r[2]);
        try o.put("low", r[3]);
        try o.put("close", r[4]);
        try out.append(o.value());
    }
    return .{ .array = out };
}

fn validPeriod(s: []const u8) bool {
    if (std.mem.eql(u8, s, "YTD")) return true;
    if (s.len < 3 or s.len > 6 or s[0] != 'P') return false;
    for (s[1..]) |c| if (!(std.ascii.isDigit(c) or std.mem.indexOfScalar(u8, "TSMHDWY", c) != null)) return false;
    return true;
}

fn defaultResolution(period: []const u8) []const u8 {
    const map = [_][2][]const u8{
        .{ "P1D", "PT15M" }, .{ "P1W", "PT1H" }, .{ "P1M", "P1D" }, .{ "P3M", "P1D" },
        .{ "P6M", "P1D" },   .{ "YTD", "P1D" },  .{ "P1Y", "P1W" }, .{ "P3Y", "P1W" },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], period)) return m[1];
    return "P1M";
}

fn productTypeId(t: []const u8) ?u16 {
    const map = [_]struct { []const u8, u16 }{
        .{ "stock", 1 },      .{ "bond", 2 },  .{ "future", 7 }, .{ "option", 8 },    .{ "fund", 13 },
        .{ "leveraged", 14 }, .{ "etf", 131 }, .{ "cfd", 535 },  .{ "warrant", 536 },
    };
    for (map) |m| if (std.ascii.eqlIgnoreCase(m[0], t)) return m[1];
    return null;
}

const order_type_names = [_][]const u8{ "LIMIT", "STOPLIMIT", "MARKET", "STOPLOSS" };

fn orderTypeId(t: []const u8) ?i64 {
    for (order_type_names, 0..) |n, i| if (std.ascii.eqlIgnoreCase(n, t)) return @intCast(i);
    return null;
}

fn orderTypeName(v: ?Value) Value {
    const x = v orelse return .null;
    const i: i64 = @intFromFloat(num(x));
    if (i < 0 or i >= order_type_names.len) return x;
    return .{ .string = order_type_names[@intCast(i)] };
}

fn timeTypeName(v: ?Value) Value {
    const x = v orelse return .null;
    return switch (@as(i64, @intFromFloat(num(x)))) {
        1 => .{ .string = "DAY" },
        3 => .{ .string = "GTC" },
        else => x,
    };
}

/// DeGiro errors are usually {"errors":[{"text":"..."}]}; fall back to the raw (truncated) body.
fn upstreamMessage(arena: std.mem.Allocator, body: []const u8) []const u8 {
    const v = std.json.parseFromSliceLeaky(Value, arena, body, .{}) catch return body[0..@min(body.len, 300)];
    const errs = field(v, "errors");
    if (errs == .array and errs.array.items.len > 0) {
        var parts: std.ArrayList(u8) = .empty;
        for (errs.array.items) |e| {
            const t = field(e, "text");
            if (t != .string) continue;
            if (parts.items.len > 0) parts.appendSlice(arena, "; ") catch {};
            parts.appendSlice(arena, t.string) catch {};
        }
        if (parts.items.len > 0) return parts.items;
    }
    return body[0..@min(body.len, 300)];
}

const read_only = "\"annotations\":{\"readOnlyHint\":true,\"openWorldHint\":true}";
const range_props =
    "\"from\":{\"type\":\"string\",\"description\":\"Start date YYYY-MM-DD (default: 30 days before 'to')\"}," ++
    "\"to\":{\"type\":\"string\",\"description\":\"End date YYYY-MM-DD (default: today)\"}";

const tool_portfolio =
    \\{"name":"get_portfolio","title":"Portfolio","description":"Current positions (size, price and break-even in the product currency, value and P/L in EUR), cash per currency, and account totals including free space per currency.","inputSchema":{"type":"object","properties":{"include_closed":{"type":"boolean","description":"Also list positions that are fully sold (size 0)"}}},
++ read_only ++ "}";
const tool_open_orders =
    \\{"name":"get_open_orders","title":"Open orders","description":"Orders that are currently open (not yet executed or cancelled).","inputSchema":{"type":"object","properties":{}},
++ read_only ++ "}";
const tool_order_history =
    \\{"name":"get_order_history","title":"Order history","description":"Every order event (create, modify, execution, rejection) in a date range of at most 90 days.","inputSchema":{"type":"object","properties":{
++ range_props ++ "}}," ++ read_only ++ "}";
const tool_transactions =
    \\{"name":"get_transactions","title":"Transactions","description":"Executed trades in a date range: price, quantity, totals and fees (in the account base currency, EUR).","inputSchema":{"type":"object","properties":{
++ range_props ++ "}}," ++ read_only ++ "}";
const tool_cash =
    \\{"name":"get_cash_movements","title":"Cash movements","description":"Account statement: deposits, withdrawals, dividends, fees, cash sweeps and trade settlements in a date range.","inputSchema":{"type":"object","properties":{
++ range_props ++ "}}," ++ read_only ++ "}";
const tool_search =
    \\{"name":"search_products","title":"Search products","description":"Find tradable products by name, symbol or ISIN. Returns product_id values needed by the other tools. The same company can be listed on several exchanges; check currency and exchange_id.","inputSchema":{"type":"object","properties":{"query":{"type":"string","description":"Name, ticker or ISIN"},"type":{"type":"string","enum":["stock","etf","bond","fund","option","future","leveraged","warrant","cfd"]},"limit":{"type":"integer","minimum":1,"maximum":50,"default":10}},"required":["query"]},
++ read_only ++ "}";
const tool_products =
    \\{"name":"get_products","title":"Product details","description":"Details for one or more product_ids: name, ISIN, currency, exchange, last close, allowed order and time types.","inputSchema":{"type":"object","properties":{"product_ids":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":50}},"required":["product_ids"]},
++ read_only ++ "}";
const tool_prices =
    \\{"name":"get_price_history","title":"Price history","description":"Live quote plus OHLC candles for a product. Times are Europe/Amsterdam.","inputSchema":{"type":"object","properties":{"product_id":{"type":"string"},"period":{"type":"string","description":"How far back: P1D, P1W, P1M, P3M, P6M, YTD, P1Y, P3Y, P5Y (default P1M)"},"resolution":{"type":"string","description":"Candle size: PT1M, PT5M, PT15M, PT1H, P1D, P1W, P1M (default depends on period)"}},"required":["product_id"]},
++ read_only ++ "}";
const tool_check_order =
    \\{"name":"check_order","title":"Check order (no execution)","description":"Validates an order with DeGiro and returns its costs and a confirmation_id. Does NOT place the order. Present the result to the user and only call confirm_order after their explicit approval.","inputSchema":{"type":"object","properties":{"product_id":{"type":"string"},"side":{"type":"string","enum":["BUY","SELL"]},"order_type":{"type":"string","enum":["LIMIT","MARKET","STOPLOSS","STOPLIMIT"]},"size":{"type":"number","exclusiveMinimum":0,"description":"Number of shares/units"},"price":{"type":"number","description":"Limit price (LIMIT, STOPLIMIT)"},"stop_price":{"type":"number","description":"Trigger price (STOPLOSS, STOPLIMIT)"},"time_type":{"type":"string","enum":["DAY","GTC"],"default":"DAY"}},"required":["product_id","side","order_type","size"]},"annotations":{"readOnlyHint":true,"openWorldHint":true}}
;
const tool_check_conversion =
    \\{"name":"check_conversion","title":"Check currency exchange (no execution)","description":"Prepares a currency exchange to or from EUR as a limit order on DeGiro's EUR/XXX product and validates it like check_order: returns the costs, what is paid and received, and a confirmation_id for confirm_order. Does NOT exchange anything. all=true converts the whole free balance of a foreign currency to EUR without overshooting it. Only call confirm_order after the user explicitly approved.","inputSchema":{"type":"object","properties":{"from":{"type":"string","description":"Currency to sell, e.g. USD"},"to":{"type":"string","description":"Currency to buy, e.g. EUR"},"amount":{"type":"number","exclusiveMinimum":0,"description":"Amount in the 'from' currency"},"all":{"type":"boolean","description":"Convert the whole free balance of 'from' (foreign to EUR only)"},"rate":{"type":"number","description":"Limit rate in XXX per EUR (default: live rate with a 0.3% margin)"}},"required":["from","to"]},"annotations":{"readOnlyHint":true,"openWorldHint":true}}
;
const tool_confirm_order =
    \\{"name":"confirm_order","title":"Place order","description":"Places an order previously validated with check_order. Real money: call this only after the user explicitly approved that exact order and its costs.","inputSchema":{"type":"object","properties":{"confirmation_id":{"type":"string"}},"required":["confirmation_id"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}}
;
const tool_cancel_order =
    \\{"name":"cancel_order","title":"Cancel order","description":"Cancels an open order by order_id (from get_open_orders).","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"}},"required":["order_id"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":true,"openWorldHint":true}}
;

const read_tools = tool_portfolio ++ "," ++ tool_open_orders ++ "," ++ tool_order_history ++ "," ++ tool_transactions ++ "," ++
    tool_cash ++ "," ++ tool_search ++ "," ++ tool_products ++ "," ++ tool_prices;
const read_tools_json = "[" ++ read_tools ++ "]";
const all_tools_json = "[" ++ read_tools ++ "," ++ tool_check_order ++ "," ++ tool_check_conversion ++ "," ++ tool_confirm_order ++ "," ++ tool_cancel_order ++ "]";

test "tool list is valid JSON" {
    for ([_][]const u8{ read_tools_json, all_tools_json }) |j| {
        const parsed = try std.json.parseFromSlice(Value, std.testing.allocator, j, .{});
        defer parsed.deinit();
        for (parsed.value.array.items) |t| try std.testing.expect(t.object.get("inputSchema") != null);
    }
}

test "flatten update rows" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const v = try std.json.parseFromSliceLeaky(Value, a,
        \\{"value":[{"name":"positionrow","id":"1","value":[{"name":"id","value":"1"},{"name":"size","value":5},{"name":"positionType","value":"PRODUCT"}]}]}
    , .{});
    const rows = try flattenRows(a, v);
    try std.testing.expectEqual(@as(usize, 1), rows.len);
    try std.testing.expect(isProduct(rows[0]));
    try std.testing.expectEqual(@as(f64, 5), num(rows[0].get("size")));
}

test "candles get timestamps" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try std.json.parseFromSliceLeaky(Value, a,
        \\{"times":"2026-10-13/P1D","data":[[0,1,2,0.5,1.5],[6,1,2,0.5,1.7]]}
    , .{});
    const c = try candles(a, s);
    try std.testing.expectEqualStrings("2026-10-19", c.array.items[1].object.get("time").?.string);
    const h = try std.json.parseFromSliceLeaky(Value, a,
        \\{"times":"2026-10-16T00:00:00/PT1H","data":[[15,1,2,0.5,1.5]]}
    , .{});
    try std.testing.expectEqualStrings("2026-10-16 15:00", (try candles(a, h)).array.items[0].object.get("time").?.string);
}

test "a confirmation_id is sealed, expires and places one order at most" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var tb: Toolbox = .{ .gpa = std.testing.allocator, .io = io, .dg = undefined, .trading = true, .key = @splat(3) };
    defer tb.deinit();

    const confirm = struct {
        fn f(t: *Toolbox, al: std.mem.Allocator, id: []const u8) !Result {
            var args: std.json.ObjectMap = .empty;
            try args.put(al, "confirmation_id", .{ .string = id });
            return t.call(al, "confirm_order", .{ .object = args });
        }
    }.f;

    const forged = try confirm(&tb, a, "bm90LWEtcmVhbC10b2tlbi1hdC1hbGwtYWJjZGVmZ2hpamtsbW5vcA");
    try std.testing.expect(forged.is_error and std.mem.startsWith(u8, forged.text, "Unknown or expired"));

    const other_key = try sealed.seal(a, io, @splat(4), .order, OrderP{ .c = "c1", .b = "{}", .s = "x", .exp = sealed.now(io) + 60 });
    try std.testing.expect((try confirm(&tb, a, other_key)).is_error);
    const expired = try sealed.seal(a, io, tb.key, .order, OrderP{ .c = "c1", .b = "{}", .s = "x", .exp = sealed.now(io) - 1 });
    try std.testing.expect((try confirm(&tb, a, expired)).is_error);
    const wrong_kind = try sealed.seal(a, io, tb.key, .access, OrderP{ .c = "c1", .b = "{}", .s = "x", .exp = sealed.now(io) + 60 });
    try std.testing.expect((try confirm(&tb, a, wrong_kind)).is_error);

    try std.testing.expect(try tb.markUsed("c1", sealed.now(io) + 60));
    try std.testing.expect(!try tb.markUsed("c1", sealed.now(io) + 60));
    const reused = try sealed.seal(a, io, tb.key, .order, OrderP{ .c = "c1", .b = "{}", .s = "x", .exp = sealed.now(io) + 60 });
    const r = try confirm(&tb, a, reused);
    try std.testing.expect(r.is_error and std.mem.indexOf(u8, r.text, "already used") != null);

    // Expired entries are dropped when the next confirmation comes in.
    try std.testing.expect(try tb.markUsed("old", sealed.now(io) - 1));
    try std.testing.expect(try tb.markUsed("c2", sealed.now(io) + 60));
    try std.testing.expect(!tb.used.contains("old"));
}

test "converting a whole balance never pays more than the balance" {
    var prng: std.Random.DefaultPrng = .init(42);
    const r = prng.random();
    for (0..10_000) |_| {
        const balance = r.float(f64) * 50_000;
        const limit = fxLimit(true, 0.5 + r.float(f64) * 2);
        const size = fxSize(true, balance, limit);
        try std.testing.expect(size * limit <= balance);
        try std.testing.expect((size + 1) * limit > balance);
    }
    try std.testing.expectEqual(@as(f64, 1.1235), fxLimit(true, 1.12341));
    try std.testing.expectEqual(@as(f64, 1.1234), fxLimit(false, 1.12349));
    try std.testing.expectEqual(@as(f64, 890), fxSize(true, 1000, 1.1235));
}
