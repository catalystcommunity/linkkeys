//! Runtime UI configuration exposed through the generated CSIL contract.

use std::path::PathBuf;

use liblinkkeys::generated::services::ServiceError;
use liblinkkeys::generated::types::{
    GetUiConfigurationResponse, PasswordPolicy, UiDisplaySettings, UiExtension, UiTheme,
};
use serde::Deserialize;

#[derive(Default, Deserialize)]
struct FileConfig {
    display: Option<DisplayConfig>,
    theme: Option<ThemeConfig>,
    #[serde(default)]
    extensions: Vec<ExtensionConfig>,
}

#[derive(Deserialize)]
struct DisplayConfig {
    site_name: Option<String>,
    support_url: Option<String>,
}

#[derive(Deserialize)]
struct ThemeConfig {
    asset_dir: Option<PathBuf>,
    stylesheet_url: Option<String>,
    logo_url: Option<String>,
    favicon_url: Option<String>,
}

#[derive(Deserialize)]
struct ExtensionConfig {
    id: String,
    asset_dir: Option<PathBuf>,
    module_url: String,
    api_version: i64,
    stylesheet_url: Option<String>,
}

#[derive(Clone)]
pub struct RuntimeExtensionAssets {
    pub id: String,
    pub asset_dir: PathBuf,
}

#[derive(Clone)]
pub struct LoadedUiConfiguration {
    pub public: GetUiConfigurationResponse,
    pub dist_dir: Option<PathBuf>,
    pub theme_dir: Option<PathBuf>,
    pub extension_assets: Vec<RuntimeExtensionAssets>,
}

pub fn load() -> Result<LoadedUiConfiguration, ServiceError> {
    let file = match std::env::var("UI_CONFIG_FILE") {
        Ok(path) => {
            let text = std::fs::read_to_string(path)
                .map_err(|error| config_error("UI_CONFIG_FILE cannot be read", error))?;
            toml::from_str::<FileConfig>(&text)
                .map_err(|error| config_error("UI_CONFIG_FILE is not valid TOML", error))?
        }
        Err(_) => FileConfig::default(),
    };
    let dist_dir = std::env::var("UI_DIST_DIR").ok().map(PathBuf::from);
    if dist_dir
        .as_deref()
        .is_some_and(|path| !path.is_dir() || !path.join("index.html").is_file())
    {
        return Err(invalid("UI_DIST_DIR must contain an index.html file"));
    }

    let mut ids = std::collections::BTreeSet::new();
    let mut extensions = Vec::new();
    let mut extension_assets = Vec::new();
    for (index, extension) in file.extensions.into_iter().enumerate() {
        let field = |name: &str| format!("extensions[{}].{name}", index + 1);
        if !valid_id(&extension.id) {
            return Err(invalid(&format!(
                "{} must use 1 to 64 letters, numbers, hyphens, or underscores",
                field("id")
            )));
        }
        if !ids.insert(extension.id.clone()) {
            return Err(invalid(&format!("{} must be unique", field("id"))));
        }
        if extension.api_version != 1 {
            return Err(invalid(&format!("{} must be 1", field("api_version"))));
        }
        if !safe_asset_url(&extension.module_url) {
            return Err(invalid(&format!(
                "{} must be a root-relative same-origin path",
                field("module_url")
            )));
        }
        if extension
            .stylesheet_url
            .as_deref()
            .is_some_and(|value| !safe_asset_url(value))
        {
            return Err(invalid(&format!(
                "{} must be a root-relative same-origin path",
                field("stylesheet_url")
            )));
        }
        if extension
            .asset_dir
            .as_deref()
            .is_some_and(|value| !value.is_dir())
        {
            return Err(invalid(&format!(
                "{} must be a directory",
                field("asset_dir")
            )));
        }
        if let Some(asset_dir) = extension.asset_dir {
            extension_assets.push(RuntimeExtensionAssets {
                id: extension.id.clone(),
                asset_dir,
            });
        }
        extensions.push(UiExtension {
            id: extension.id,
            module_url: extension.module_url,
            api_version: extension.api_version,
            stylesheet_url: extension.stylesheet_url,
        });
    }

    let (theme, theme_dir) = match file.theme {
        Some(value) => {
            if value
                .asset_dir
                .as_deref()
                .is_some_and(|path| !path.is_dir())
            {
                return Err(invalid("theme.asset_dir must be a directory"));
            }
            for (name, url) in [
                ("theme.stylesheet_url", &value.stylesheet_url),
                ("theme.logo_url", &value.logo_url),
                ("theme.favicon_url", &value.favicon_url),
            ] {
                if url.as_deref().is_some_and(|url| !safe_asset_url(url)) {
                    return Err(invalid(&format!(
                        "{name} must be a root-relative same-origin path"
                    )));
                }
            }
            (
                Some(UiTheme {
                    stylesheet_url: value.stylesheet_url,
                    logo_url: value.logo_url,
                    favicon_url: value.favicon_url,
                }),
                value.asset_dir,
            )
        }
        None => (None, None),
    };

    let display = file.display.unwrap_or(DisplayConfig {
        site_name: None,
        support_url: None,
    });
    if display
        .support_url
        .as_deref()
        .is_some_and(|value| !safe_support_url(value))
    {
        return Err(invalid(
            "display.support_url must be an HTTP or HTTPS URL without credentials",
        ));
    }
    let site_name = display.site_name.unwrap_or_else(|| "LinkKeys".to_string());
    if site_name.trim().is_empty() || site_name.len() > 100 {
        return Err(invalid("display.site_name must contain 1 to 100 bytes"));
    }
    let public_origin = std::env::var("PUBLIC_ORIGIN").ok();
    if public_origin
        .as_deref()
        .is_some_and(|value| crate::services::notification::validate_public_origin(value).is_err())
    {
        return Err(invalid("PUBLIC_ORIGIN must be a valid HTTPS origin"));
    }

    Ok(LoadedUiConfiguration {
        public: GetUiConfigurationResponse {
            host_api_version: 1,
            domain: crate::conversions::get_domain_name(),
            public_origin,
            capabilities: current_capabilities(),
            display: UiDisplaySettings {
                site_name,
                support_url: display.support_url,
            },
            theme,
            extensions,
            password_policy: Some(PasswordPolicy {
                min_length: crate::services::password::MIN_PASSWORD_LENGTH as i64,
                max_length: crate::services::password::MAX_PASSWORD_LENGTH as i64,
            }),
        },
        dist_dir,
        theme_dir,
        extension_assets,
    })
}

pub fn configuration() -> Result<GetUiConfigurationResponse, ServiceError> {
    load().map(|value| public_configuration(&value))
}

pub fn public_configuration(loaded: &LoadedUiConfiguration) -> GetUiConfigurationResponse {
    let mut public = loaded.public.clone();
    public.capabilities = current_capabilities();
    public
}

fn current_capabilities() -> Vec<String> {
    let mut capabilities = vec!["account".to_string(), "runtime_extensions".to_string()];
    if crate::services::password::authentication_enabled() {
        capabilities.push("password_login".to_string());
    }
    capabilities.extend(
        crate::services::notification::capabilities()
            .capabilities
            .into_iter()
            .map(|value| value.purpose),
    );
    capabilities
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn safe_asset_url(value: &str) -> bool {
    if !value.starts_with('/') || value.starts_with("//") || value.contains(['\\', '\r', '\n']) {
        return false;
    }
    let base = reqwest::Url::parse("https://linkkeys.invalid/").expect("valid fixed origin");
    base.join(value)
        .is_ok_and(|url| url.origin() == base.origin())
}

fn safe_support_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn config_error(context: &str, error: impl std::fmt::Display) -> ServiceError {
    let message = format!("{context}: {error}");
    log::error!("Runtime UI configuration error: {message}");
    invalid(&message)
}

fn invalid(message: &str) -> ServiceError {
    ServiceError {
        code: 500,
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{safe_asset_url, safe_support_url};

    #[test]
    fn asset_urls_are_root_relative_and_cannot_change_the_origin() {
        assert!(safe_asset_url("/_linkkeys/extensions/product/extension.js"));
        assert!(!safe_asset_url("https://example.test/extension.js"));
        assert!(!safe_asset_url("//example.test/extension.js"));
        assert!(!safe_asset_url("/\\example.test/extension.js"));
        assert!(!safe_asset_url("extension.js"));
    }

    #[test]
    fn support_urls_reject_embedded_credentials() {
        assert!(safe_support_url("https://support.example.test/help"));
        assert!(!safe_support_url(
            "https://user:secret@support.example.test/help"
        ));
        assert!(!safe_support_url("javascript:alert(1)"));
    }
}
