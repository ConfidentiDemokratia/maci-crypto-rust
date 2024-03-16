// This function should be launchable form SWIFT
pub fn add_rust(left: i32, right: i32) -> i32 {
    left + right
}

#[cfg(test)]
mod tests {
    use crate::add_rust;

    #[test]
    fn it_works() {
        let result = add_rust(2, 2);
        assert_eq!(result, 4);
    }
}
