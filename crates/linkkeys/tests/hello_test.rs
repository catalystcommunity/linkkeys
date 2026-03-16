use linkkeys::services::hello::HelloHandler;

#[test]
fn test_hello_default_name() {
    let handler = HelloHandler;
    let greeting = handler.hello(None);
    assert_eq!(greeting, "Hello, world!");
}

#[test]
fn test_hello_custom_name() {
    let handler = HelloHandler;
    let greeting = handler.hello(Some("LinkKeys".into()));
    assert_eq!(greeting, "Hello, LinkKeys!");
}

#[test]
fn test_hello_empty_string_name() {
    let handler = HelloHandler;
    let greeting = handler.hello(Some("".into()));
    assert_eq!(greeting, "Hello, !");
}
