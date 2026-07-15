use std::fmt;

use reqwest::Url;

/// POI runtime endpoint whose formatting is always redacted.
///
/// Network code must explicitly expose the wrapped URL at the request boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveUrl(Url);

impl SensitiveUrl {
    #[must_use]
    pub const fn expose_url(&self) -> &Url {
        &self.0
    }

    #[must_use]
    pub fn into_exposed_url(self) -> Url {
        self.0
    }
}

impl From<Url> for SensitiveUrl {
    fn from(url: Url) -> Self {
        Self(url)
    }
}

impl fmt::Debug for SensitiveUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitiveUrl(<redacted>)")
    }
}

impl fmt::Display for SensitiveUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted POI URL>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formatting_is_redacted_and_explicit_exposure_is_exact() {
        let raw = Url::parse(
            "https://user-sentinel:password-sentinel@host-sentinel.invalid/path-sentinel?query=query-sentinel#fragment-sentinel",
        )
        .expect("sentinel URL");
        let sensitive = SensitiveUrl::from(raw.clone());

        for formatted in [format!("{sensitive}"), format!("{sensitive:?}")] {
            for sentinel in [
                "https",
                "user-sentinel",
                "password-sentinel",
                "host-sentinel",
                "path-sentinel",
                "query-sentinel",
                "fragment-sentinel",
            ] {
                assert!(
                    !formatted.contains(sentinel),
                    "leaked {sentinel}: {formatted}"
                );
            }
        }
        assert_eq!(sensitive.expose_url(), &raw);
        assert_eq!(sensitive.into_exposed_url(), raw);
    }
}
