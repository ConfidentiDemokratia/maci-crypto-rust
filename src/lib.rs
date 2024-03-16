uniffi::include_scaffolding!("example"); // "example" is the name of the .udl file

fn add(a: u32, b: u32) -> u32 {
    a + b
}

fn hello() -> String {
    "This is a hello from the rust library".to_string()
}
