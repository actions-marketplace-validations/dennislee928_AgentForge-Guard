//! A tiny service library.

/// Add two numbers without overflowing.
pub fn add(a: u32, b: u32) -> Option<u32> {
    a.checked_add(b)
}

#[cfg(test)]
mod tests {
    #[test]
    fn adds() {
        assert_eq!(super::add(2, 2), Some(4));
        assert_eq!(super::add(u32::MAX, 1), None);
    }
}
