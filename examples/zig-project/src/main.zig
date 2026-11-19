const std = @import("std");

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

pub fn main() void {
    std.debug.print("{d}\n", .{add(2, 3)});
}

test "add" {
    try std.testing.expectEqual(@as(i32, 5), add(2, 3));
}
