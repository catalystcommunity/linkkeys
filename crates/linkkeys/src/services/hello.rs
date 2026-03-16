/// Hello service handler.
///
/// Once csilgen produces valid traits, this will implement the generated Hello trait.
/// For now it uses local types matching the CSIL definitions.
pub struct HelloHandler;

impl HelloHandler {
    pub fn hello(&self, name: Option<String>) -> String {
        let name = name.unwrap_or_else(|| "world".to_string());
        format!("Hello, {}!", name)
    }
}
