//! Tera template engine wrapper.
//!
//! Provides template loading, rendering, and management.

use std::path::Path;
use std::sync::Arc;

use tera::{Context, Tera};
use tracing::{debug, info};

use crate::error::DaemonError;

/// Template engine for rendering configuration files.
///
/// Wraps Tera and provides a simplified interface for template operations.
#[derive(Clone)]
pub struct TemplateEngine {
    tera: Arc<Tera>,
}

impl TemplateEngine {
    /// Create a new template engine, loading templates from the specified directory.
    ///
    /// Templates are loaded recursively from the directory with `.tera` extension.
    pub fn new(template_dir: &Path) -> Result<Self, DaemonError> {
        let pattern = template_dir.join("**/*.tera");
        let pattern_str = pattern.to_string_lossy();

        debug!(pattern = %pattern_str, "Loading templates");

        let tera = Tera::new(&pattern_str).map_err(|e| DaemonError::Template {
            message: format!("Failed to load templates from '{}': {}", template_dir.display(), e),
        })?;

        let template_count = tera.get_template_names().count();
        info!(
            directory = %template_dir.display(),
            count = template_count,
            "Template engine initialized"
        );

        Ok(Self {
            tera: Arc::new(tera),
        })
    }

    /// Create a template engine with no templates (for testing or when templates aren't needed).
    pub fn empty() -> Self {
        Self {
            tera: Arc::new(Tera::default()),
        }
    }

    /// Render a template with the given context.
    ///
    /// # Arguments
    ///
    /// * `template_name` - Name of the template (e.g., "nginx/site.conf.tera")
    /// * `context` - JSON value containing template variables
    ///
    /// # Returns
    ///
    /// The rendered template content as a string.
    pub fn render(
        &self,
        template_name: &str,
        context: &serde_json::Value,
    ) -> Result<String, DaemonError> {
        // Convert JSON context to Tera context
        let tera_context = Context::from_serialize(context).map_err(|e| DaemonError::Template {
            message: format!("Invalid template context: {}", e),
        })?;

        // Render the template
        self.tera
            .render(template_name, &tera_context)
            .map_err(|e| DaemonError::Template {
                message: format!("Failed to render template '{}': {}", template_name, e),
            })
    }

    /// Check if a template exists.
    pub fn has_template(&self, name: &str) -> bool {
        self.tera.get_template_names().any(|n| n == name)
    }

    /// List all available template names.
    pub fn list_templates(&self) -> Vec<&str> {
        self.tera.get_template_names().collect()
    }

    /// Get the number of loaded templates.
    pub fn template_count(&self) -> usize {
        self.tera.get_template_names().count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    fn create_test_template_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();

        // Create a simple test template
        // Note: We use write_all to avoid format string interpretation of {{ as {
        let template_path = dir.path().join("test.conf.tera");
        let mut file = fs::File::create(&template_path).unwrap();
        file.write_all(b"# Config for {{ name }}\n").unwrap();
        file.write_all(b"setting = {{ value }}\n").unwrap();

        dir
    }

    #[test]
    fn test_new_engine() {
        let dir = create_test_template_dir();
        let engine = TemplateEngine::new(dir.path()).unwrap();

        assert!(engine.template_count() >= 1);
        assert!(engine.has_template("test.conf.tera"));
    }

    #[test]
    fn test_empty_engine() {
        let engine = TemplateEngine::empty();
        assert_eq!(engine.template_count(), 0);
    }

    #[test]
    fn test_render_template() {
        let dir = create_test_template_dir();
        let engine = TemplateEngine::new(dir.path()).unwrap();

        let context = serde_json::json!({
            "name": "test-service",
            "value": 42
        });

        let result = engine.render("test.conf.tera", &context).unwrap();
        assert!(result.contains("# Config for test-service"));
        assert!(result.contains("setting = 42"));
    }

    #[test]
    fn test_missing_template() {
        let engine = TemplateEngine::empty();
        let context = serde_json::json!({});

        let result = engine.render("nonexistent.tera", &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_templates() {
        let dir = create_test_template_dir();
        let engine = TemplateEngine::new(dir.path()).unwrap();

        let templates = engine.list_templates();
        assert!(templates.contains(&"test.conf.tera"));
    }
}
